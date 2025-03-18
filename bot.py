from curl_cffi import requests
from fake_useragent import FakeUserAgent
from datetime import datetime
from colorama import *
import asyncio
import json
import os
import time
import pytz

# Initialize Colorama
init()

# Timezone setup
wib = pytz.timezone('Asia/Jakarta')

class RateLimiter:
    def __init__(self, rate_limit: int, interval: float):
        self.rate_limit = rate_limit
        self.interval = interval
        self.semaphore = asyncio.Semaphore(rate_limit)
        self.last_call = 0

    async def __aenter__(self):
        await self.semaphore.acquire()
        now = asyncio.get_event_loop().time()
        elapsed = now - self.last_call
        if elapsed < self.interval:
            await asyncio.sleep(self.interval - elapsed)
        self.last_call = asyncio.get_event_loop().time()
        return self

    async def __aexit__(self, *args):
        self.semaphore.release()

class NaorisProtocol:
    def __init__(self):
        self.headers = {
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7",
            "Origin": "chrome-extension://cpikalnagknmlfhnilhfelifgbollmmp",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "none",
            "User-Agent": FakeUserAgent().random
        }
        self.proxies = []
        self.proxy_index = 0
        self.account_proxies = {}
        self.rate_limiter = RateLimiter(rate_limit=5, interval=1)
        self.shutdown_event = asyncio.Event()

    #region Utility Methods
    def mask_account(self, account):
        """Mask account address for secure logging"""
        return f"{account[:6]}****{account[-4:]}" if len(account) > 10 else account

    def print_message(self, address, proxy, color, message):
        """Standardized logging format"""
        print(
            f"{Fore.CYAN + Style.BRIGHT}[{datetime.now().astimezone(wib).strftime('%x %X')}]"
            f"{Fore.WHITE} {self.mask_account(address)}"
            f"{Fore.MAGENTA}@{proxy.split('@')[-1] if proxy else 'NoProxy'}"
            f"{color} {message}{Style.RESET_ALL}"
        )

    def get_next_proxy(self, account):
        """Get or assign proxy for account"""
        if account not in self.account_proxies or not self.account_proxies[account]:
            if not self.proxies:
                return None
            proxy = self.proxies[self.proxy_index % len(self.proxies)]
            self.proxy_index += 1
            self.account_proxies[account] = self._format_proxy(proxy)
        return self.account_proxies[account]

    def rotate_proxy(self, account):
        """Force proxy rotation for account"""
        if self.proxies:
            self.account_proxies[account] = self._format_proxy(
                self.proxies[self.proxy_index % len(self.proxies)]
            )
            self.proxy_index += 1
        return self.account_proxies.get(account)

    def _format_proxy(self, proxy):
        """Ensure proper proxy formatting"""
        schemes = ("http://", "https://", "socks4://", "socks5://")
        return proxy if proxy.startswith(schemes) else f"http://{proxy}"
    #endregion

    #region Core Functionality
    async def get_access_token(self, address: str, use_proxy: bool):
        """Token acquisition with automatic refresh"""
        token = None
        proxy = self.get_next_proxy(address) if use_proxy else None
        for _ in range(3):
            try:
                async with self.rate_limiter:
                    response = await asyncio.to_thread(
                        requests.post,
                        url="https://naorisprotocol.network/sec-api/auth/generateToken",
                        headers={
                            **self.headers,
                            "Content-Type": "application/json",
                            "Content-Length": str(len(json.dumps({"wallet_address": address})))
                        },
                        data=json.dumps({"wallet_address": address}),
                        proxy=proxy,
                        timeout=15,
                        impersonate="chrome110"
                    )
                response.raise_for_status()
                token = response.json().get('token')
                if token:
                    self.print_message(address, proxy, Fore.GREEN, "Token acquired")
                    return token
            except Exception as e:
                self.print_message(address, proxy, Fore.RED, f"Auth failed: {str(e)}")
                proxy = self.rotate_proxy(address) if use_proxy else None
                await asyncio.sleep(5)
        return None

    async def maintain_session(self, address: str, device_hash: int, use_proxy: bool):
        """Main session management loop"""
        while not self.shutdown_event.is_set():
            token = await self.get_access_token(address, use_proxy)
            if not token:
                await asyncio.sleep(10)
                continue

            try:
                tasks = [
                    asyncio.create_task(self.heartbeat_loop(address, token, use_proxy)),
                    asyncio.create_task(self.protection_loop(address, device_hash, token, use_proxy)),
                    asyncio.create_task(self.token_refresh_loop(address, token, use_proxy))
                ]
                await asyncio.gather(*tasks)
            except Exception as e:
                self.print_message(address, None, Fore.RED, f"Session crashed: {str(e)}")
                await asyncio.sleep(5)

    async def token_refresh_loop(self, address: str, token: str, use_proxy: bool):
        """Refresh token every 15 minutes"""
        last_refresh = time.time()
        while not self.shutdown_event.is_set():
            if time.time() - last_refresh > 900:  # 15 minutes
                new_token = await self.get_access_token(address, use_proxy)
                if new_token:
                    token = new_token
                    last_refresh = time.time()
                await asyncio.sleep(60)
            else:
                await asyncio.sleep(10)
    #endregion

    #region Heartbeat System
    async def heartbeat_loop(self, address: str, token: str, use_proxy: bool):
        """Enhanced heartbeat with session recovery"""
        while not self.shutdown_event.is_set():
            proxy = self.get_next_proxy(address) if use_proxy else None
            try:
                async with self.rate_limiter:
                    response = await asyncio.to_thread(
                        requests.post,
                        url="https://beat.naorisprotocol.network/api/ping",
                        headers={
                            **self.headers,
                            "Authorization": f"Bearer {token}",
                            "Content-Type": "application/json"
                        },
                        json={
                            "wallet_address": address,
                            "timestamp": int(time.time())
                        },
                        proxy=proxy,
                        timeout=10,
                        impersonate="chrome110"
                    )

                # Handle 410 Gone (session expired)
                if response.status_code == 410:
                    self.print_message(address, proxy, Fore.YELLOW, "Session expired - renewing...")
                    return await self.renew_session(address, use_proxy)
                    
                response.raise_for_status()
                
                data = response.json()
                if not data.get("success", False):
                    raise ValueError(f"Server rejection: {data.get('message', 'Unknown error')}")

                self.print_message(address, proxy, Fore.GREEN, "✓ Heartbeat")
                await asyncio.sleep(8)

            except Exception as e:
                self.print_message(address, proxy, Fore.RED, f"Heartbeat error: {str(e)}")
                await self.handle_heartbeat_failure(address, use_proxy)

    async def renew_session(self, address: str, use_proxy: bool):
        """Full session renewal sequence"""
        self.print_message(address, None, Fore.CYAN, "Starting session renewal")
        
        # Get fresh token
        new_token = await self.get_access_token(address, use_proxy)
        if not new_token:
            return False

        # Re-run activation flow
        account = next((a for a in self.load_accounts() if a['Address'] == address), None)
        if not account or 'deviceHash' not in account:
            return False

        success = await self.activate_protection(
            address=address,
            device_hash=account['deviceHash'],
            token=new_token,
            proxy=self.get_next_proxy(address) if use_proxy else None
        )
        
        if success:
            self.print_message(address, None, Fore.GREEN, "Session renewed successfully")
            return True
            
        self.print_message(address, None, Fore.RED, "Session renewal failed")
        return False

    async def handle_heartbeat_failure(self, address: str, use_proxy: bool):
        """Automated recovery from failures"""
        self.rotate_proxy(address)
        
        for attempt in range(3):
            await asyncio.sleep(2 ** attempt)
            if await self.renew_session(address, use_proxy):
                return
                
        self.print_message(address, None, Fore.YELLOW, "Initiating full restart")
        await self.maintain_session(address, use_proxy)
    #endregion

    #region Protection System
    async def protection_loop(self, address: str, device_hash: int, token: str, use_proxy: bool):
        """Enhanced protection management"""
        while not self.shutdown_event.is_set():
            proxy = self.get_next_proxy(address) if use_proxy else None
            try:
                status = await self.get_protection_status(address, token, proxy)
                if status == "active":
                    await asyncio.sleep(60)
                    continue

                success = await self.activate_protection(address, device_hash, token, proxy)
                if success:
                    self.print_message(address, proxy, Fore.GREEN, "Protection active")
                    await asyncio.sleep(60)
                else:
                    await asyncio.sleep(10)

            except Exception as e:
                self.print_message(address, proxy, Fore.RED, f"Protection error: {str(e)}")
                await asyncio.sleep(10)

    async def get_protection_status(self, address: str, token: str, proxy: str):
        """Check current protection status"""
        try:
            async with self.rate_limiter:
                response = await asyncio.to_thread(
                    requests.post,
                    url="https://naorisprotocol.network/sec-api/api/status",
                    headers={
                        **self.headers,
                        "Authorization": f"Bearer {token}"
                    },
                    json={"walletAddress": address},
                    proxy=proxy,
                    timeout=15,
                    impersonate="chrome110"
                )
            return response.json().get("state", "unknown")
        except:
            return "error"

    async def activate_protection(self, address: str, device_hash: int, token: str, proxy: str):
        """Robust activation sequence"""
        for _ in range(3):
            try:
                # Deactivate first
                await asyncio.to_thread(
                    requests.post,
                    url="https://naorisprotocol.network/sec-api/api/switch",
                    headers={
                        **self.headers,
                        "Authorization": f"Bearer {token}"
                    },
                    json={
                        "walletAddress": address,
                        "state": "OFF",
                        "deviceHash": device_hash
                    },
                    proxy=proxy,
                    timeout=15,
                    impersonate="chrome110"
                )

                # Activate
                response = await asyncio.to_thread(
                    requests.post,
                    url="https://naorisprotocol.network/sec-api/api/switch",
                    headers={
                        **self.headers,
                        "Authorization": f"Bearer {token}"
                    },
                    json={
                        "walletAddress": address,
                        "state": "ON",
                        "deviceHash": device_hash
                    },
                    proxy=proxy,
                    timeout=15,
                    impersonate="chrome110"
                )

                if "Session started" in response.text:
                    return True
            except Exception as e:
                self.print_message(address, proxy, Fore.YELLOW, f"Activation attempt failed: {str(e)}")
                await asyncio.sleep(5)
        return False
    #endregion

    #region Setup & Main Flow
    def load_accounts(self):
        """Improved account validation with type conversion"""
        try:
            with open('accounts.json') as f:
                accounts = json.load(f)
            
            if not isinstance(accounts, list):
                raise ValueError("Accounts file must contain an array")
            
            valid_accounts = []
            for idx, acc in enumerate(accounts, 1):
                try:
                    address = acc.get("Address", "").lower().strip()
                    if not address.startswith("0x") or len(address) != 42:
                        raise ValueError(f"Invalid Ethereum address format")
                    
                    device_hash = acc.get("deviceHash")
                    if isinstance(device_hash, str) and device_hash.isdigit():
                        device_hash = int(device_hash)
                    if not isinstance(device_hash, int):
                        raise ValueError(f"deviceHash must be numeric")
                    
                    valid_accounts.append({
                        "Address": address,
                        "deviceHash": device_hash
                    })
                    
                except Exception as e:
                    self.print_message(address, None, Fore.YELLOW, f"Account {idx} error: {str(e)}")
        
            if not valid_accounts:
                raise ValueError("No valid accounts found in file")
            
            return valid_accounts
            
        except Exception as e:
            self.print_message("SYSTEM", None, Fore.RED, f"Config Error: {str(e)}")
            return []

    async def main(self):
        """Main entry point"""
        try:
            self.clear_terminal()
            self.welcome()
            
            accounts = self.load_accounts()
            if not accounts:
                self.print_message("SYSTEM", None, Fore.RED, "No valid accounts found!")
                return

            proxy_choice = self.get_proxy_choice()
            use_proxy = proxy_choice in (1, 2)
            
            if use_proxy:
                await self.load_proxies(proxy_choice)
                if not self.proxies:
                    self.print_message("SYSTEM", None, Fore.RED, "No proxies available!")
                    return

            self.print_message("SYSTEM", None, Fore.CYAN, f"Starting {len(accounts)} accounts...")
            
            tasks = []
            for account in accounts:
                tasks.append(asyncio.create_task(
                    self.maintain_session(
                        account['Address'],
                        account['deviceHash'],
                        use_proxy
                    )
                ))
            
            await asyncio.gather(*tasks)
            
        except KeyboardInterrupt:
            self.shutdown_event.set()
        finally:
            self.print_message("SYSTEM", None, Fore.CYAN, "Shutting down...")
            await asyncio.sleep(1)

    def get_proxy_choice(self):
        """Get user proxy preference"""
        while True:
            try:
                print(f"{Fore.CYAN}Choose proxy mode:")
                print(f"1. Use public proxies")
                print(f"2. Use private proxies")
                print(f"3. No proxies")
                choice = int(input("Selection (1-3): "))
                if 1 <= choice <= 3:
                    return choice
                print(f"{Fore.RED}Invalid choice!{Style.RESET_ALL}")
            except ValueError:
                print(f"{Fore.RED}Enter a number!{Style.RESET_ALL}")

    async def load_proxies(self, choice: int):
        """Load proxies based on user choice"""
        try:
            if choice == 1:
                response = await asyncio.to_thread(
                    requests.get,
                    url="https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/all.txt",
                    timeout=15
                )
                self.proxies = response.text.splitlines()
                with open('proxy.txt', 'w') as f:
                    f.write("\n".join(self.proxies))
            else:
                with open('proxy.txt') as f:
                    self.proxies = [line.strip() for line in f if line.strip()]
            
            self.proxies = [self._format_proxy(p) for p in self.proxies]
            self.print_message("SYSTEM", None, Fore.GREEN, f"Loaded {len(self.proxies)} proxies")
        except Exception as e:
            self.print_message("SYSTEM", None, Fore.RED, f"Proxy load failed: {str(e)}")
            self.proxies = []

    def clear_terminal(self):
        """Clear terminal screen"""
        os.system('cls' if os.name == 'nt' else 'clear')

    def welcome(self):
        """Show welcome message"""
        print(f"{Fore.GREEN}Naoris Protocol Node Manager{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Secure Node Management System{Style.RESET_ALL}")
        print("-" * 50)
    #endregion

if __name__ == "__main__":
    bot = NaorisProtocol()
    try:
        asyncio.run(bot.main())
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}Shutdown initiated...{Style.RESET_ALL}")

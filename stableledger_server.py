"""
Shepherd Backend Server
Wraps the on-chain scanner in an HTTP API the browser UI calls.

Usage:
    python stableledger_server.py

Then open http://localhost:8090 in your browser.
"""

import json
import os
import sys
import time
import threading
import ssl
ssl._create_default_https_context = ssl._create_unverified_context
import urllib.error
import urllib.request
from datetime import datetime, timezone
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path


# ======================== SCANNER (self-contained) ========================

class BaseStablecoinLedger:
    USDC_CONTRACT = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"
    USDC_DECIMALS = 6
    TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
    RPC_URL = "https://base-mainnet.g.alchemy.com/v2/j5z3ffA4ndMffb9Me4jLt"

    def __init__(self, watched_wallet, eth_usd_price=1700.00, chunk_size=10):
        self.watched_wallet = watched_wallet.lower()
        self.eth_usd_price = eth_usd_price
        self.chunk_size = chunk_size
        self._receipt_cache = {}
        self.progress = {"phase": "", "pct": 0, "found": 0}

    def _rpc(self, method, params, retries=3):
        payload = {"jsonrpc": "2.0", "method": method, "params": params, "id": 1}
        body = json.dumps(payload).encode("utf-8")
        last_err = None
        for attempt in range(retries):
            try:
                req = urllib.request.Request(self.RPC_URL, data=body,
                    headers={"Content-Type": "application/json"})
                with urllib.request.urlopen(req, timeout=15) as resp:
                    result = json.loads(resp.read().decode())
                if "error" in result:
                    raise RuntimeError(f"RPC error: {result['error']}")
                return result.get("result")
            except urllib.error.HTTPError as e:
                err_body = e.read().decode() if hasattr(e, 'read') else ""
                last_err = f"HTTP {e.code}: {err_body[:200]}"
                time.sleep(0.5 * (2 ** attempt))
            except (urllib.error.URLError, TimeoutError) as e:
                last_err = e
                time.sleep(0.5 * (2 ** attempt))
        raise RuntimeError(f"RPC failed after {retries} retries: {last_err}")

    @staticmethod
    def _addr_to_topic(addr):
        return "0x" + ("0" * 24) + addr.lower().replace("0x", "")

    @staticmethod
    def _topic_to_addr(topic):
        return "0x" + topic[-40:].lower()

    def latest_block(self):
        return int(self._rpc("eth_blockNumber", []), 16)

    def _get_logs_chunked(self, from_block, to_block, topics, label=""):
        out = []
        cur = from_block
        total = to_block - from_block + 1
        while cur <= to_block:
            end = min(cur + self.chunk_size - 1, to_block)
            done = cur - from_block
            pct = int(done / total * 100) if total > 0 else 100
            self.progress = {"phase": label, "pct": pct, "found": len(out)}
            logs = self._rpc("eth_getLogs", [{
                "address": self.USDC_CONTRACT, "topics": topics,
                "fromBlock": hex(cur), "toBlock": hex(end),
            }])
            if logs:
                out.extend(logs)
            cur = end + 1
        self.progress = {"phase": label, "pct": 100, "found": len(out)}
        return out

    def scan_usdc_transfers(self, from_block, to_block):
        wallet_topic = self._addr_to_topic(self.watched_wallet)
        outflows = self._get_logs_chunked(from_block, to_block,
            topics=[self.TRANSFER_TOPIC, wallet_topic], label="Outflows")
        inflows = self._get_logs_chunked(from_block, to_block,
            topics=[self.TRANSFER_TOPIC, None, wallet_topic], label="Inflows")
        transfers = []
        for log in outflows:
            transfers.append(self._decode_log(log, "outflow"))
        for log in inflows:
            transfers.append(self._decode_log(log, "inflow"))
        transfers.sort(key=lambda t: (t["block_number"], t["log_index"]))
        return transfers

    def _decode_log(self, log, direction):
        topics = log["topics"]
        return {
            "direction": direction,
            "from": self._topic_to_addr(topics[1]),
            "to": self._topic_to_addr(topics[2]),
            "amount": int(log["data"], 16) / (10 ** self.USDC_DECIMALS),
            "tx_hash": log["transactionHash"],
            "block_number": int(log["blockNumber"], 16),
            "log_index": int(log["logIndex"], 16),
        }

    def _receipt(self, tx_hash):
        if tx_hash in self._receipt_cache:
            return self._receipt_cache[tx_hash]
        r = self._rpc("eth_getTransactionReceipt", [tx_hash])
        self._receipt_cache[tx_hash] = r
        return r

    def _gas_usd_for_outflow(self, tx_hash):
        r = self._receipt(tx_hash)
        if not r or r.get("status") != "0x1":
            return 0.0, 0.0
        gas_used = int(r.get("gasUsed", "0x0"), 16)
        gas_price = int(r.get("effectiveGasPrice", "0x0"), 16)
        gas_eth = (gas_used * gas_price) / 10**18
        return gas_eth, round(gas_eth * self.eth_usd_price, 6)

    def compile_journal(self, transfer):
        amt = round(transfer["amount"], 2)
        counterparty = transfer["to"] if transfer["direction"] == "outflow" else transfer["from"]
        if transfer["direction"] == "outflow":
            gas_eth, gas_usd = self._gas_usd_for_outflow(transfer["tx_hash"])
            lines = [
                {"line": 1, "account": "AP / Expense (unclassified)", "debit": amt, "credit": 0.0,
                 "memo": f"USDC out to {counterparty}"},
                {"line": 2, "account": "Digital Asset - USDC (Base)", "debit": 0.0, "credit": amt,
                 "memo": "USDC sent"},
            ]
            if gas_usd > 0:
                lines += [
                    {"line": 3, "account": "Expense - Network Fees", "debit": gas_usd, "credit": 0.0,
                     "memo": f"Gas {gas_eth:.8f} ETH @ ${self.eth_usd_price}"},
                    {"line": 4, "account": "Digital Asset - ETH (gas)", "debit": 0.0, "credit": gas_usd,
                     "memo": "Gas consumed"},
                ]
        else:
            lines = [
                {"line": 1, "account": "Digital Asset - USDC (Base)", "debit": amt, "credit": 0.0,
                 "memo": f"USDC in from {counterparty}"},
                {"line": 2, "account": "AR / Revenue (unclassified)", "debit": 0.0, "credit": amt,
                 "memo": "USDC received"},
            ]
            gas_eth, gas_usd = 0.0, 0.0

        total_debit = round(sum(l["debit"] for l in lines), 2)
        total_credit = round(sum(l["credit"] for l in lines), 2)
        return {
            "tx_hash": transfer["tx_hash"],
            "block_number": transfer["block_number"],
            "direction": transfer["direction"],
            "asset": "USDC",
            "amount": amt,
            "counterparty": counterparty,
            "gas_usd": gas_usd,
            "total_debit": total_debit,
            "total_credit": total_credit,
            "is_balanced": total_debit == total_credit,
            "journal_lines": lines,
        }

    def build_report(self, from_block, to_block):
        transfers = self.scan_usdc_transfers(from_block, to_block)
        self.progress = {"phase": "Building journals", "pct": 50, "found": len(transfers)}
        journals = []
        for i, t in enumerate(transfers):
            journals.append(self.compile_journal(t))
            if len(transfers) > 0:
                self.progress = {"phase": "Building journals", "pct": 50 + int(50 * i / len(transfers)), "found": len(transfers)}
        total_in = round(sum(j["amount"] for j in journals if j["direction"] == "inflow"), 2)
        total_out = round(sum(j["amount"] for j in journals if j["direction"] == "outflow"), 2)
        total_gas = round(sum(j["gas_usd"] for j in journals), 6)
        self.progress = {"phase": "Done", "pct": 100, "found": len(transfers)}
        return {
            "wallet": self.watched_wallet,
            "scan_range": {"from_block": from_block, "to_block": to_block},
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "transfer_count": len(journals),
                "inflow_count": sum(1 for j in journals if j["direction"] == "inflow"),
                "outflow_count": sum(1 for j in journals if j["direction"] == "outflow"),
                "total_usdc_in": total_in,
                "total_usdc_out": total_out,
                "net_usdc": round(total_in - total_out, 2),
                "total_gas_usd": total_gas,
                "all_balanced": all(j["is_balanced"] for j in journals),
            },
            "journals": journals,
        }


# ======================== SOLANA SCANNER ========================

class SolanaStablecoinLedger:
    USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
    USDC_DECIMALS = 6
    RPC_URL = "https://mainnet.helius-rpc.com/?api-key=8344d6de-09ea-425c-a80b-9696150a7c43"
    SOL_USD_PRICE = 70

    def __init__(self, watched_wallet, tx_limit=50):
        self.watched_wallet = watched_wallet
        self.tx_limit = tx_limit
        self.progress = {"phase": "", "pct": 0, "found": 0}

    def _rpc(self, method, params, retries=3):
        payload = {"jsonrpc": "2.0", "method": method, "params": params, "id": 1}
        body = json.dumps(payload).encode("utf-8")
        last_err = None
        for attempt in range(retries):
            try:
                req = urllib.request.Request(self.RPC_URL, data=body,
                    headers={"Content-Type": "application/json"})
                with urllib.request.urlopen(req, timeout=20) as resp:
                    result = json.loads(resp.read().decode())
                if "error" in result:
                    raise RuntimeError(f"RPC error: {result['error']}")
                return result.get("result")
            except urllib.error.HTTPError as e:
                err_body = e.read().decode() if hasattr(e, 'read') else ""
                last_err = f"HTTP {e.code}: {err_body[:200]}"
                time.sleep(1.0 * (2 ** attempt))
            except (urllib.error.URLError, TimeoutError) as e:
                last_err = e
                time.sleep(1.0 * (2 ** attempt))
        raise RuntimeError(f"Solana RPC failed after {retries} retries: {last_err}")

    def scan_usdc_transfers(self):
        self.progress = {"phase": "Fetching signatures", "pct": 2, "found": 0}

        # Paginate: Solana caps at 1000 per call
        all_sigs = []
        remaining = self.tx_limit
        before = None
        while remaining > 0:
            batch_size = min(remaining, 1000)
            params = {"limit": batch_size}
            if before:
                params["before"] = before
            sigs = self._rpc("getSignaturesForAddress", [self.watched_wallet, params])
            if not sigs:
                break
            all_sigs.extend(sigs)
            before = sigs[-1]["signature"]
            remaining -= len(sigs)
            self.progress = {"phase": "Fetching signatures", "pct": 2, "found": len(all_sigs)}
            if len(sigs) < batch_size:
                break  # no more history

        if not all_sigs:
            return []

        transfers = []
        total = len(all_sigs)
        for i, sig_info in enumerate(all_sigs):
            pct = int((i / total) * 93) + 5
            self.progress = {"phase": "Parsing transactions", "pct": pct, "found": len(transfers)}

            if sig_info.get("err"):
                continue  # skip failed txs

            try:
                tx = self._rpc("getTransaction", [
                    sig_info["signature"],
                    {"encoding": "jsonParsed", "maxSupportedTransactionVersion": 0}
                ])
            except Exception:
                continue

            if not tx or not tx.get("meta"):
                continue

            transfer = self._extract_usdc_transfer(tx, sig_info["signature"])
            if transfer:
                transfers.append(transfer)

        self.progress = {"phase": "Done", "pct": 100, "found": len(transfers)}
        transfers.sort(key=lambda t: t["slot"])
        return transfers

    def _extract_usdc_transfer(self, tx, signature):
        """Extract USDC transfer from parsed Solana transaction."""
        meta = tx["meta"]
        pre_tokens = meta.get("preTokenBalances") or []
        post_tokens = meta.get("postTokenBalances") or []
        slot = tx.get("slot", 0)

        # Build balance maps: {owner: amount} for USDC pre and post
        def token_map(balances):
            m = {}
            for b in balances:
                if b.get("mint") == self.USDC_MINT:
                    owner = b.get("owner", "")
                    amt = float(b.get("uiTokenAmount", {}).get("uiAmount") or 0)
                    m[owner] = amt
            return m

        pre = token_map(pre_tokens)
        post = token_map(post_tokens)

        # Find our wallet's balance change
        pre_bal = pre.get(self.watched_wallet, 0)
        post_bal = post.get(self.watched_wallet, 0)
        delta = round(post_bal - pre_bal, 2)

        if abs(delta) < 0.01:
            return None  # no meaningful USDC change

        direction = "inflow" if delta > 0 else "outflow"
        amount = abs(delta)

        # Find counterparty: the other address whose USDC balance changed oppositely
        counterparty = "unknown"
        all_owners = set(list(pre.keys()) + list(post.keys()))
        for owner in all_owners:
            if owner == self.watched_wallet:
                continue
            other_delta = (post.get(owner, 0)) - (pre.get(owner, 0))
            if (direction == "outflow" and other_delta > 0) or \
               (direction == "inflow" and other_delta < 0):
                counterparty = owner
                break

        # Fee in SOL
        fee_lamports = meta.get("fee", 0)
        fee_sol = fee_lamports / 1e9
        fee_usd = round(fee_sol * self.SOL_USD_PRICE, 6)
        # Only attribute fee if our wallet sent the tx
        account_keys = []
        msg = tx.get("transaction", {}).get("message", {})
        for ak in msg.get("accountKeys", []):
            if isinstance(ak, dict):
                account_keys.append(ak.get("pubkey", ""))
            else:
                account_keys.append(ak)
        is_signer = len(account_keys) > 0 and account_keys[0] == self.watched_wallet

        return {
            "direction": direction,
            "from": self.watched_wallet if direction == "outflow" else counterparty,
            "to": counterparty if direction == "outflow" else self.watched_wallet,
            "amount": amount,
            "tx_hash": signature,
            "block_number": slot,
            "slot": slot,
            "log_index": 0,
            "fee_sol": fee_sol if is_signer else 0,
            "fee_usd": fee_usd if is_signer else 0,
        }

    def compile_journal(self, transfer):
        amt = round(transfer["amount"], 2)
        cp = transfer["to"] if transfer["direction"] == "outflow" else transfer["from"]
        fee_usd = transfer.get("fee_usd", 0)

        if transfer["direction"] == "outflow":
            lines = [
                {"line": 1, "account": "AP / Expense (unclassified)", "debit": amt, "credit": 0.0,
                 "memo": f"USDC out to {cp[:8]}..."},
                {"line": 2, "account": "Digital Asset - USDC (Solana)", "debit": 0.0, "credit": amt,
                 "memo": "USDC sent"},
            ]
            if fee_usd > 0:
                lines += [
                    {"line": 3, "account": "Expense - Network Fees", "debit": fee_usd, "credit": 0.0,
                     "memo": f"Solana fee {transfer['fee_sol']:.6f} SOL @ ${self.SOL_USD_PRICE}"},
                    {"line": 4, "account": "Digital Asset - SOL (gas)", "debit": 0.0, "credit": fee_usd,
                     "memo": "SOL consumed"},
                ]
        else:
            lines = [
                {"line": 1, "account": "Digital Asset - USDC (Solana)", "debit": amt, "credit": 0.0,
                 "memo": f"USDC in from {cp[:8]}..."},
                {"line": 2, "account": "AR / Revenue (unclassified)", "debit": 0.0, "credit": amt,
                 "memo": "USDC received"},
            ]
            fee_usd = 0

        total_debit = round(sum(l["debit"] for l in lines), 2)
        total_credit = round(sum(l["credit"] for l in lines), 2)
        return {
            "tx_hash": transfer["tx_hash"],
            "block_number": transfer.get("slot", 0),
            "direction": transfer["direction"],
            "asset": "USDC",
            "amount": amt,
            "counterparty": cp,
            "gas_usd": fee_usd,
            "total_debit": total_debit,
            "total_credit": total_credit,
            "is_balanced": total_debit == total_credit,
            "journal_lines": lines,
        }

    def build_report(self):
        transfers = self.scan_usdc_transfers()
        journals = [self.compile_journal(t) for t in transfers]
        total_in = round(sum(j["amount"] for j in journals if j["direction"] == "inflow"), 2)
        total_out = round(sum(j["amount"] for j in journals if j["direction"] == "outflow"), 2)
        total_gas = round(sum(j["gas_usd"] for j in journals), 6)
        return {
            "wallet": self.watched_wallet,
            "chain": "solana",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "transfer_count": len(journals),
                "inflow_count": sum(1 for j in journals if j["direction"] == "inflow"),
                "outflow_count": sum(1 for j in journals if j["direction"] == "outflow"),
                "total_usdc_in": total_in,
                "total_usdc_out": total_out,
                "net_usdc": round(total_in - total_out, 2),
                "total_gas_usd": total_gas,
                "all_balanced": all(j["is_balanced"] for j in journals),
            },
            "journals": journals,
        }


# ======================== HTTP SERVER ========================

# Configure AI provider: "claude" or "gemini"
AI_PROVIDER = os.environ.get("AI_PROVIDER", "claude")  # toggle here
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")

def classify_transaction(tx_data, chart_of_accounts, prior_classifications, client_profile=None):
    """Use AI to suggest a GL classification for an unknown transaction."""
    # Build the prompt (same for both providers)
    prior_summary = ""
    if prior_classifications:
        for p in prior_classifications[:30]:
            prior_summary += f"- {p['counterparty'][:12]}...: {p['count']}x classified as \"{p['gl_code']}\" "
            prior_summary += f"({p['direction']}, avg ${p['avg_amount']:.2f}"
            if p.get('pattern'):
                prior_summary += f", {p['pattern']}"
            prior_summary += ")\n"

    coa_text = "\n".join(f"- {code}" for code in chart_of_accounts if code != "Unclassified")

    # Build client context
    biz_context = ""
    if client_profile:
        parts = []
        if client_profile.get('business_type'):
            parts.append(f"Business type: {', '.join(client_profile['business_type'])}")
        if client_profile.get('typical_transactions'):
            parts.append(f"Typical transactions: {', '.join(client_profile['typical_transactions'])}")
        if client_profile.get('notes'):
            parts.append(f"Additional context: {client_profile['notes']}")
        if parts:
            biz_context = "\n".join(parts)

    prompt = f"""You are a crypto accounting transaction classifier for Shepherd, a stablecoin accounting product.

Given a blockchain transaction and the customer's context, suggest the most likely GL code from their chart of accounts.

CHART OF ACCOUNTS:
{coa_text}

CLIENT CONTEXT:
{biz_context if biz_context else "No client context provided."}

PRIOR CLASSIFICATIONS BY THIS CUSTOMER:
{prior_summary if prior_summary else "No prior classifications yet."}

TRANSACTION TO CLASSIFY:
- Direction: {tx_data.get('direction', 'unknown')}
- Amount: ${tx_data.get('amount', 0):,.2f}
- Counterparty address: {tx_data.get('counterparty', 'unknown')}
- Chain: {tx_data.get('chain', 'unknown')}
- Block/Slot: {tx_data.get('block', 'unknown')}

Consider:
1. Does the amount/timing match patterns in prior classifications?
2. Is the counterparty similar to previously classified addresses?
3. Based on amount size and direction, what category is most likely?
4. Round amounts ($5000, $10000) often suggest payroll or planned payments
5. Small irregular amounts often suggest SaaS or operational costs
6. Inflows are typically revenue, outflows are typically expenses

Respond with ONLY valid JSON, no markdown, no backticks:
{{"gl_code": "the full GL code string from the chart of accounts", "confidence": 0.0 to 1.0, "reasoning": "one sentence explanation"}}"""

    if AI_PROVIDER == "gemini":
        return _classify_gemini(prompt)
    else:
        return _classify_claude(prompt)


def _classify_claude(prompt):
    if not ANTHROPIC_API_KEY:
        return {"gl_code": None, "confidence": 0, "reasoning": "No ANTHROPIC_API_KEY set."}
    for attempt in range(3):
        try:
            payload = {
                "model": "claude-haiku-4-5-20251001",
                "max_tokens": 200,
                "messages": [{"role": "user", "content": prompt}]
            }
            req = urllib.request.Request(
                "https://api.anthropic.com/v1/messages",
                data=json.dumps(payload).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "x-api-key": ANTHROPIC_API_KEY,
                    "anthropic-version": "2023-06-01",
                }
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                result = json.loads(resp.read().decode())
            text = result.get("content", [{}])[0].get("text", "")
            text = text.strip().replace("```json", "").replace("```", "").strip()
            return json.loads(text)
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            if attempt < 2:
                wait = (attempt + 1) * 2
                print(f"  [Claude] Timeout, retrying in {wait}s...")
                time.sleep(wait)
                continue
            print(f"  [Claude] Error: {e}")
            return {"gl_code": None, "confidence": 0, "reasoning": f"Connection error: {str(e)[:80]}"}
        except Exception as e:
            print(f"  [Claude] Error: {e}")
            return {"gl_code": None, "confidence": 0, "reasoning": f"Claude error: {str(e)[:100]}"}


def _classify_gemini(prompt):
    if not GEMINI_API_KEY:
        return {"gl_code": None, "confidence": 0, "reasoning": "No GEMINI_API_KEY set."}
    for attempt in range(3):
        try:
            payload = {
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {"maxOutputTokens": 200, "temperature": 0.1}
            }
            url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={GEMINI_API_KEY}"
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                result = json.loads(resp.read().decode())
            text = result.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "")
            text = text.strip().replace("```json", "").replace("```", "").strip()
            return json.loads(text)
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt < 2:
                wait = (attempt + 1) * 2
                print(f"  [Gemini] Rate limited, waiting {wait}s...")
                time.sleep(wait)
                continue
            print(f"  [Gemini] Error: {e}")
            return {"gl_code": None, "confidence": 0, "reasoning": f"Gemini error: {str(e)[:100]}"}
        except Exception as e:
            print(f"  [Gemini] Error: {e}")
            return {"gl_code": None, "confidence": 0, "reasoning": f"Gemini error: {str(e)[:100]}"}

def detect_chain(wallet):
    """0x + 42 chars = EVM/Base. Otherwise assume Solana (base58)."""
    if wallet.startswith("0x") and len(wallet) == 42:
        return "base"
    return "solana"

# Global state for active scan
active_scan = {"running": False, "engine": None, "result": None, "error": None}

def run_scan(wallet, lookback, from_block=None):
    global active_scan
    try:
        chain = detect_chain(wallet)
        if chain == "base":
            engine = BaseStablecoinLedger(wallet)
            active_scan["engine"] = engine
            to_block = engine.latest_block()
            if from_block is not None:
                scan_from = from_block
            else:
                scan_from = to_block - lookback
            print(f"  [Base] Scanning {wallet}, blocks {scan_from:,} -> {to_block:,}")
            report = engine.build_report(scan_from, to_block)
        else:
            engine = SolanaStablecoinLedger(wallet, tx_limit=lookback)
            active_scan["engine"] = engine
            print(f"  [Solana] Scanning {wallet}, last {lookback} transactions")
            report = engine.build_report()

        active_scan["result"] = report
        active_scan["error"] = None
        print(f"  Done: {report['summary']['transfer_count']} USDC transfers found")
    except Exception as e:
        active_scan["error"] = str(e)
        active_scan["result"] = None
        print(f"  Error: {e}")
    finally:
        active_scan["running"] = False


class Handler(SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            html_path = Path(__file__).parent / "stableledger_demo.html"
            if html_path.exists():
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(html_path.read_bytes())
            else:
                self.send_error(404, f"Put stableledger_demo.html next to this script")
            return

        if self.path == "/api/progress":
            self.send_response(200)
            self._cors()
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            prog = {}
            if active_scan.get("engine"):
                prog = active_scan["engine"].progress
            self.wfile.write(json.dumps({
                "running": active_scan["running"],
                "progress": prog,
                "error": active_scan.get("error"),
            }).encode())
            return

        if self.path == "/api/result":
            self.send_response(200)
            self._cors()
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            if active_scan.get("result"):
                self.wfile.write(json.dumps(active_scan["result"], ensure_ascii=True).encode())
            elif active_scan.get("error"):
                self.wfile.write(json.dumps({"error": active_scan["error"]}).encode())
            else:
                self.wfile.write(b'{"error":"No scan results yet"}')
            return

        self.send_error(404)

    def do_POST(self):
        if self.path == "/api/classify":
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length).decode()) if length else {}

            tx_data = body.get("transaction", {})
            coa = body.get("chart_of_accounts", [])
            prior = body.get("prior_classifications", [])
            profile = body.get("client_profile", None)

            print(f"  [{AI_PROVIDER.title()}] Classifying: ${tx_data.get('amount',0):,.2f} {tx_data.get('direction','?')} to {tx_data.get('counterparty','?')[:16]}...")
            suggestion = classify_transaction(tx_data, coa, prior, profile)
            print(f"  [{AI_PROVIDER.title()}] Suggested: {suggestion.get('gl_code','?')} ({suggestion.get('confidence',0):.0%})")

            self.send_response(200)
            self._cors()
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(suggestion, ensure_ascii=True).encode())
            return

        if self.path == "/api/scan":
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length).decode()) if length else {}
            wallet = body.get("wallet", "").strip()
            lookback = int(body.get("lookback_blocks", 1000))

            is_evm = wallet.startswith("0x") and len(wallet) == 42
            is_solana = not wallet.startswith("0x") and 32 <= len(wallet) <= 44
            if not is_evm and not is_solana:
                self.send_response(400)
                self._cors()
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Invalid wallet address"}).encode())
                return

            if active_scan["running"]:
                self.send_response(409)
                self._cors()
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Scan already running"}).encode())
                return

            active_scan["running"] = True
            active_scan["result"] = None
            active_scan["error"] = None
            from_block = body.get("from_block")
            print(f"\n[SCAN] Starting for {wallet}, lookback={lookback}" + (f", from_block={from_block}" if from_block else ""))
            threading.Thread(target=run_scan, args=(wallet, lookback, from_block), daemon=True).start()

            self.send_response(200)
            self._cors()
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "started"}).encode())
            return

        self.send_error(404)

    def do_OPTIONS(self):
        self.send_response(200)
        self._cors()
        self.end_headers()

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def log_message(self, format, *args):
        # Quiet down request logging, keep our own prints
        pass


if __name__ == "__main__":
    port = 8090
    print(f"Shepherd server starting on http://localhost:{port}")
    print(f"Open that URL in your browser.")
    if AI_PROVIDER == "gemini" and GEMINI_API_KEY:
        print(f"AI classification: Gemini Flash (enabled)")
    elif AI_PROVIDER == "claude" and ANTHROPIC_API_KEY:
        print(f"AI classification: Claude Haiku (enabled)")
    else:
        print(f"AI classification: disabled (set ANTHROPIC_API_KEY or GEMINI_API_KEY)")
        print(f"  Current provider: {AI_PROVIDER}")
    print()
    server = HTTPServer(("", port), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.server_close()

import re
import httpx
from typing import Any, Dict, List, Optional
from config import settings

# Expresión regular para detectar direcciones públicas base58 de Solana (32-44 caracteres)
SOLANA_ADDRESS_REGEX = re.compile(r"\b[1-9A-HJ-NP-za-km-z]{32,44}\b")

# RPC público gratuito de Solana (Cero costo de gas ni suscripciones)
DEFAULT_SOLANA_RPC = "https://api.mainnet-beta.solana.com"


def extract_solana_addresses(text: str) -> List[str]:
    """Busca y extrae direcciones públicas de Solana dentro del texto del mensaje."""
    # Descartar palabras comunes o hashes que no sean direcciones válidas
    candidates = SOLANA_ADDRESS_REGEX.findall(text)
    valid_addresses = []
    for c in candidates:
        # Longitud típica de una clave pública de Solana (suele ser entre 32 y 44 caracteres)
        if 32 <= len(c) <= 44:
            # Excluir URLs comunes o fragmentos que coincidan por error
            if not any(prefix in c.lower() for prefix in ["http", "discord", "token"]):
                valid_addresses.append(c)
    return list(set(valid_addresses))[:3]  # Máximo 3 para auditoría rápida


async def audit_solana_address(address: str, rpc_url: Optional[str] = None) -> Dict[str, Any]:
    """
    Consulta en tiempo real la blockchain de Solana vía JSON-RPC gratuito.
    Extrae saldo, si es un contrato inteligente o billetera, y actividad reciente.
    """
    target_rpc = rpc_url or getattr(settings, "SOLANA_RPC_URL", DEFAULT_SOLANA_RPC)

    payload_balance = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getBalance",
        "params": [address, {"commitment": "confirmed"}],
    }

    payload_signatures = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "getSignaturesForAddress",
        "params": [address, {"limit": 5}],
    }

    try:
        async with httpx.AsyncClient(timeout=2.5) as client:
            # Consulta 1: Saldo on-chain
            resp_bal = await client.post(target_rpc, json=payload_balance)
            bal_data = resp_bal.json() if resp_bal.status_code == 200 else {}
            lamports = bal_data.get("result", {}).get("value", 0)
            sol_balance = round(lamports / 1_000_000_000, 4)

            # Consulta 2: Historial de firmas / actividad
            resp_sig = await client.post(target_rpc, json=payload_signatures)
            sig_data = resp_sig.json() if resp_sig.status_code == 200 else {}
            signatures = sig_data.get("result", [])

            tx_count = len(signatures)
            is_new_account = tx_count < 3

            risk_level = "ALTO (Billetera nueva / Desechable)" if is_new_account else "MODERADO"

            return {
                "detected": True,
                "address": address,
                "balance_sol": sol_balance,
                "recent_tx_count": tx_count,
                "is_new_account": is_new_account,
                "risk_assessment": risk_level,
                "network": "Solana Mainnet",
            }
    except Exception as e:
        return {
            "detected": True,
            "address": address,
            "error": f"Consulta RPC no disponible: {str(e)}",
            "risk_assessment": "DESCONOCIDO",
        }


async def scan_solana_threats(text: str) -> Optional[Dict[str, Any]]:
    """
    Sensor pasivo: Si el mensaje contiene una dirección de Solana,
    realiza la auditoría on-chain sin costo. Si no, retorna None en 0ms.
    """
    addresses = extract_solana_addresses(text)
    if not addresses:
        return None  # Mensaje sin direcciones de Solana (0ms overhead)

    # Auditar la primera dirección detectada
    return await audit_solana_address(addresses[0])

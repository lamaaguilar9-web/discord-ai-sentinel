import json
import re
import time
import httpx
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse

from config import settings

# Patrones de detección rápida (Heurística de nivel 0)
URL_REGEX = re.compile(r"https?://[^\s/$.?#].[^\s]*", re.IGNORECASE)
MASS_MENTION_REGEX = re.compile(r"@(everyone|here)", re.IGNORECASE)

# Palabras gatillo de ingeniería social y ataques en Web3
DECEPTIVE_KEYWORDS = {
    "airdrop",
    "claim",
    "mint",
    "whitelist",
    "wl",
    "giveaway",
    "free sol",
    "support",
    "ticket",
    "helpdesk",
    "connect wallet",
    "sync wallet",
    "validate wallet",
    "migration",
    "compensate",
    "bonus",
    "presale",
    "drainer",
}

SYSTEM_PROMPT = """Eres el motor de inteligencia de ciberseguridad 'Sentinel Guard' para servidores de Discord en Web3 y Solana.
Tu misión es proteger a la comunidad de estafas sofisticadas, drenadores de billeteras y robo de credenciales.

Analiza la INTENCIÓN real del mensaje. Evalúa patrones comunes:
1. FALSOS AIRDROPS O RECOMPENSAS: Enlaces urgentes para 'reclamar' tokens gratuitos, airdrops sorpresas o 'compensaciones'.
2. SUPLANTACIÓN Y SOPORTE FALSO: Ofrecer ayuda técnica por DM, solicitar conectar la billetera a sitios externos o sincronizar nodos.
3. ANUNCIOS FRAUDULENTOS POR WEBHOOK HACKEADO: Mensajes con tono oficial y urgente anunciando mints sorpresa o migraciones obligatorias.
4. DRENADORES DE BILLETERA (DRAINERS): Sitios diseñados para vaciar SOL, NFTs o tokens SPL mediante firmas maliciosas.

Responde ÚNICAMENTE un objeto JSON estricto con el siguiente esquema:
{
  "is_malicious": boolean,
  "confidence": float (entre 0.0 y 1.0),
  "attack_vector": "AIRDROP_SCAM" | "FAKE_SUPPORT" | "COMPROMISED_WEBHOOK" | "WALLET_DRAINER" | "PHISHING" | "NONE",
  "reason": "Explicación concisa y técnica en español del motivo por el cual es o no sospechoso."
}
No incluyas formato Markdown ni texto fuera del JSON.
"""


def extract_domains(text: str) -> list[str]:
    """Extrae los nombres de dominio de todas las URLs presentes en el texto."""
    domains = []
    for match in URL_REGEX.finditer(text):
        try:
            parsed = urlparse(match.group(0))
            netloc = parsed.netloc.lower().split(":")[0]  # Sin puerto
            # Remover subdominio 'www.'
            if netloc.startswith("www."):
                netloc = netloc[4:]
            domains.append(netloc)
        except Exception:
            continue
    return domains


def should_inspect(
    content: str,
    is_webhook: bool,
    mentions_count: int,
) -> Tuple[bool, str]:
    """
    Regla de pre-filtrado: Descarta el 95-98% del tráfico plano.
    Solo activa la IA si existe una bandera de riesgo real.
    """
    # 1. Regla crítica: Todo mensaje de Webhook con URL externa DEBE ser analizado
    domains = extract_domains(content)
    has_urls = len(domains) > 0

    if is_webhook and has_urls:
        # Si todos los dominios son 100% seguros y oficiales (ej: github.com), omitir
        if all(d in settings.SAFE_DOMAINS for d in domains):
            return False, "Webhook con dominios oficiales seguros"
        return True, "Webhook con enlace externo no verificado (Riesgo de compromiso)"

    # 2. Menciones masivas (@everyone, @here)
    if MASS_MENTION_REGEX.search(content) or mentions_count >= 3:
        if has_urls:
            return True, "Mención masiva combinada con enlaces externos"

    # 3. Presencia de palabras engañosas con enlaces
    content_lower = content.lower()
    has_trigger_words = any(word in content_lower for word in DECEPTIVE_KEYWORDS)

    if has_urls and has_trigger_words:
        # Verificar si todos los links son de la lista blanca
        if all(d in settings.SAFE_DOMAINS for d in domains):
            return False, "Enlace de dominio oficial verificado"
        return True, "Enlace externo con palabras de ingeniería social"

    # 4. Mensajes cortos con URL (típico spam de bots)
    if has_urls and len(content.strip()) < 120:
        if not all(d in settings.SAFE_DOMAINS for d in domains):
            return True, "Mensaje corto con enlace externo no verificado"

    return False, "Tráfico normal sin patrones de riesgo"


async def analyze_semantic_intent(
    text: str,
    author_metadata: str,
) -> Dict[str, Any]:
    """
    Consulta Gemini Flash para clasificar la intención semántica del mensaje.
    Retorna métricas de confianza, vector de ataque, motivo y latencia.
    """
    start_time = time.perf_counter()

    # --------------------------------------------------------------------------
    # 1. Prioridad: OpenRouter API (Con saldo del usuario)
    # --------------------------------------------------------------------------
    if settings.OPENROUTER_API_KEY:
        openrouter_url = "https://openrouter.ai/api/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {settings.OPENROUTER_API_KEY}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://discord-ai-sentinel.local",
            "X-Title": "Discord AI Sentinel Web3",
        }
        payload = {
            "model": settings.OPENROUTER_MODEL,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"--- METADATOS DEL REMITENTE ---\n{author_metadata}\n\n"
                        f"--- MENSAJE A EVALUAR ---\n\"\"\"{text}\"\"\""
                    ),
                },
            ],
            "temperature": 0.1,
            "response_format": {"type": "json_object"},
        }

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(openrouter_url, headers=headers, json=payload)
                latency = round((time.perf_counter() - start_time) * 1000, 2)

                if resp.status_code == 200:
                    body = resp.json()
                    raw_content = body["choices"][0]["message"]["content"]
                    # Limpieza de backticks en caso de que el modelo los incluya
                    clean_content = raw_content.strip()
                    if clean_content.startswith("```json"):
                        clean_content = clean_content[7:]
                    if clean_content.startswith("```"):
                        clean_content = clean_content[3:]
                    if clean_content.endswith("```"):
                        clean_content = clean_content[:-3]
                    
                    data = json.loads(clean_content.strip())
                    data["latency_ms"] = latency
                    return data
                else:
                    return {
                        "is_malicious": False,
                        "confidence": 0.0,
                        "attack_vector": "API_ERROR",
                        "reason": f"Error HTTP {resp.status_code} desde OpenRouter: {resp.text[:120]}",
                        "latency_ms": latency,
                    }
        except Exception as e:
            latency = round((time.perf_counter() - start_time) * 1000, 2)
            return {
                "is_malicious": False,
                "confidence": 0.0,
                "attack_vector": "EXCEPTION",
                "reason": f"Fallo de conexión con OpenRouter: {str(e)}",
                "latency_ms": latency,
            }

    # --------------------------------------------------------------------------
    # 2. Alternativa: Google Gemini API Directo
    # --------------------------------------------------------------------------
    if settings.GEMINI_API_KEY:
        url = (
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"{settings.GEMINI_MODEL}:generateContent?key={settings.GEMINI_API_KEY}"
        )

        payload = {
            "contents": [
                {
                    "role": "user",
                    "parts": [
                        {
                            "text": (
                                f"{SYSTEM_PROMPT}\n\n"
                                f"--- METADATOS DEL REMITENTE ---\n{author_metadata}\n\n"
                                f"--- MENSAJE A EVALUAR ---\n\"\"\"{text}\"\"\""
                            )
                        }
                    ],
                }
            ],
            "generationConfig": {
                "temperature": 0.1,
                "response_mime_type": "application/json",
            },
        }

        try:
            async with httpx.AsyncClient(timeout=3.5) as client:
                resp = await client.post(url, json=payload)
                latency = round((time.perf_counter() - start_time) * 1000, 2)

                if resp.status_code == 200:
                    body = resp.json()
                    raw_json = body["candidates"][0]["content"]["parts"][0]["text"]
                    data = json.loads(raw_json)
                    data["latency_ms"] = latency
                    return data
                else:
                    return {
                        "is_malicious": False,
                        "confidence": 0.0,
                        "attack_vector": "API_ERROR",
                        "reason": f"Error HTTP {resp.status_code} desde Gemini API",
                        "latency_ms": latency,
                    }
        except Exception as e:
            latency = round((time.perf_counter() - start_time) * 1000, 2)
            return {
                "is_malicious": False,
                "confidence": 0.0,
                "attack_vector": "EXCEPTION",
                "reason": f"Fallo de conexión en AI Guard: {str(e)}",
                "latency_ms": latency,
            }

    # --------------------------------------------------------------------------
    # 3. Fallback: Simulación Heurística Offline (Cuando no hay ninguna clave)
    # --------------------------------------------------------------------------
    latency = round((time.perf_counter() - start_time) * 1000, 2)
    lower = text.lower()
    
    if any(w in lower for w in ["sincroniza", "sync", "ticket", "helpdesk", "valida tu nodo", "validator"]):
        return {
            "is_malicious": True,
            "confidence": 0.92,
            "attack_vector": "FAKE_SUPPORT",
            "reason": "Detección heurística: solicitud no solicitada de validación de nodo o sincronización de billetera.",
            "latency_ms": latency,
        }
    
    if any(w in lower for w in ["migrar", "migration", "vulnerabilidad", "congelados", "anuncio oficial"]):
        return {
            "is_malicious": True,
            "confidence": 0.98,
            "attack_vector": "COMPROMISED_WEBHOOK",
            "reason": "Detección heurística: urgencia artificial anunciando migración obligatoria de fondos.",
            "latency_ms": latency,
        }

    if any(w in lower for w in ["airdrop", "claim", "free sol", "connect wallet", "drainer", "giveaway"]):
        return {
            "is_malicious": True,
            "confidence": 0.95,
            "attack_vector": "AIRDROP_SCAM",
            "reason": "Detección heurística: promesa de airdrop o reclamo de fondos no verificado.",
            "latency_ms": latency,
        }

    return {
        "is_malicious": False,
        "confidence": 0.1,
        "attack_vector": "NONE",
        "reason": "Mensaje informativo o de conversación sin intención dañina.",
        "latency_ms": latency,
    }

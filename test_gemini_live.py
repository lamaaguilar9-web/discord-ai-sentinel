# -*- coding: utf-8 -*-
"""
Script de verificación en vivo para Discord AI Sentinel (Gemini Direct & Latencia).
Simula la ejecución del comando !test directamente sobre analyze_semantic_intent.
"""
import asyncio
import os
import sys
import time

# Asegurar codificación UTF-8
if sys.stdout.encoding != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from dotenv import load_dotenv

# Cargar variables de entorno locales o del servicio
env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
load_dotenv(env_path)

from sentinel_discord_bot import analyze_semantic_intent, Config

async def run_live_test():
    print("=" * 70)
    print("  DISCORD AI SENTINEL — TEST DE LATENCIA Y VERIFICACIÓN EN VIVO")
    print("=" * 70)
    print(f"Motor Configurado: {Config.get_ai_engine_label()}")
    print(f"GEMINI_API_KEY Configurada: {'SÍ (Presente)' if bool(Config.GEMINI_API_KEY) else 'NO (Vacía)'}")
    print(f"OPENROUTER_API_KEY Configurada: {'SÍ (Presente)' if bool(Config.OPENROUTER_API_KEY) else 'NO (Vacía - Regla GLM)'}")
    print("-" * 70)

    test_prompt = "URGENTE: Reclama 50 SOL de airdrop exclusivo en https://solana-foundation-airdrop-claim.com antes de que expire!"
    author_info = "Verificación en Vivo | GLM P5-R1a"

    print(f"Texto de Prueba: {test_prompt}")
    print("Enviando petición a analyze_semantic_intent...")
    
    t0 = time.perf_counter()
    result = await analyze_semantic_intent(test_prompt, author_info)
    total_t = round((time.perf_counter() - t0) * 1000, 2)

    print("-" * 70)
    print("RESULTADO DE EVALUACIÓN SEMÁNTICA:")
    print(f"  • ¿Es Malicioso?   : {'🚨 SÍ' if result.get('is_malicious') else '✅ NO'}")
    print(f"  • Confianza        : {result.get('confidence', 0.0) * 100:.1f}%")
    print(f"  • Vector           : {result.get('attack_vector')}")
    print(f"  • Motivo           : {result.get('reason')}")
    print(f"  • Latencia Motor   : {result.get('latency_ms')} ms")
    print(f"  • Latencia Total   : {total_t} ms")
    print("=" * 70)

    if Config.GEMINI_API_KEY and "Fail-Secure" not in result.get("reason", "") and "Motor Heurístico" not in result.get("reason", ""):
        print("✅ VERIFICACIÓN EXITOSA: Gemini Directo respondió en vivo con baja latencia.")
        return 0
    elif not Config.GEMINI_API_KEY:
        print("⚠️ AVISO: GEMINI_API_KEY no está configurada, se ejecutó fallback.")
        return 1
    else:
        print("⚠️ AVISO: Se activó contingencia Fail-Secure.")
        return 2

if __name__ == "__main__":
    code = asyncio.run(run_live_test())
    sys.exit(code)

"""
Simulador offline de ataques Web3 para probar el motor semántico de Discord AI Sentinel.
Permite evaluar la precisión, latencia y respuesta sin depender de la conexión a Discord.
"""

import asyncio
import sys

# Force UTF-8 on Windows console
if sys.stdout.encoding != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from ai_guard import should_inspect, analyze_semantic_intent

TEST_SCENARIOS = [
    {
        "name": "1. Conversación habitual legítima",
        "author": "TraderSol (320 días)",
        "is_webhook": False,
        "mentions": 0,
        "text": "Hola a todos, ¿cómo ven el volumen de SOL hoy? Creo que romperá resistencia pronto.",
    },
    {
        "name": "2. Enlace oficial seguro (GitHub)",
        "author": "DevSol (150 días)",
        "is_webhook": False,
        "mentions": 0,
        "text": "Les dejo la documentación oficial del SDK de Solana: https://github.com/solana-labs/solana",
    },
    {
        "name": "3. Phishing clásico: Falso Airdrop masivo",
        "author": "ClaimBot99 (1 día)",
        "is_webhook": False,
        "mentions": 1,
        "text": "@everyone ¡URGENTE! Superteam y Solana lanzaron un airdrop sorpresa de $2,000 USDC para holders. Reclama tu asignación en los próximos 15 minutos aquí: https://solana-airdrop-reward-claim.xyz",
    },
    {
        "name": "4. Suplantación de Moderador / Falso Soporte",
        "author": "Mod_Support_Helper (2 días)",
        "is_webhook": False,
        "mentions": 0,
        "text": "Hola amigo, veo que tienes problemas conectando Phantom. Por favor sincroniza tu billetera y valida tu nodo en el portal oficial: https://node-wallet-validator-portal.net para resolver tu ticket.",
    },
    {
        "name": "5. Ataque Crítico: Webhook Comprometido",
        "author": "Official Announcements (Webhook)",
        "is_webhook": True,
        "mentions": 1,
        "text": "@everyone ANUNCIO OFICIAL: Hemos detectado una vulnerabilidad en el contrato inteligente. Es obligatorio migrar todos los tokens antes de medianoche en https://migration-token-solana-security.link o los fondos quedarán congelados.",
    },
]


async def run_simulation():
    print("=" * 80)
    print("🧪 SIMULACIÓN DEL MOTOR DE INTELIGENCIA DE SEGURIDAD (DISCORD AI SENTINEL)")
    print("=" * 80)

    for scenario in TEST_SCENARIOS:
        print(f"\n▶ Escenario: {scenario['name']}")
        print(f"  Remitente: {scenario['author']} | Webhook: {scenario['is_webhook']}")
        print(f"  Mensaje: \"{scenario['text'][:70]}...\"")

        # 1. Pre-filtro Heurístico
        flagged, reason = should_inspect(
            content=scenario["text"],
            is_webhook=scenario["is_webhook"],
            mentions_count=scenario["mentions"],
        )

        if not flagged:
            print(f"  [PRE-FILTRO]: ✅ OMITIDO -> {reason} (0ms de latencia, 0 costo de API)")
            continue

        print(f"  [PRE-FILTRO]: 🔍 BANDERA ACTIVADA -> {reason}")
        print("  Consultando clasificador semántico con IA...")

        # 2. Análisis Semántico
        result = await analyze_semantic_intent(
            text=scenario["text"],
            author_metadata=f"Nombre: {scenario['author']} | Es Webhook: {scenario['is_webhook']}",
        )

        is_mal = result.get("is_malicious", False)
        conf = result.get("confidence", 0.0)
        vector = result.get("attack_vector", "N/A")
        latency = result.get("latency_ms", 0.0)
        diag = result.get("reason", "")

        status_emoji = "🚨 AMENAZA BLOQUEADA" if (is_mal and conf >= 0.85) else ("⚠️ SOSPECHA EN REVISIÓN" if is_mal else "✅ PERMITIDO")

        print(f"  [VEREDICTO IA]: {status_emoji}")
        print(f"    - Confianza: {conf * 100:.1f}%")
        print(f"    - Vector: {vector}")
        print(f"    - Latencia: {latency} ms")
        print(f"    - Diagnóstico: {diag}")

    print("\n" + "=" * 80)
    print("✅ Simulación completada con éxito.")
    print("=" * 80)


if __name__ == "__main__":
    asyncio.run(run_simulation())

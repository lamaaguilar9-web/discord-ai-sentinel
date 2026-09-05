import logging
import sys

# Force UTF-8 on Windows console
if sys.stdout.encoding != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

import os
import re
import discord
from discord import app_commands
from discord.ext import commands

from datetime import datetime, timezone
from config import settings
from ai_guard import should_inspect, analyze_semantic_intent
from solana_audit import scan_solana_threats
from moderation import (
    is_author_whitelisted,
    get_account_age_days,
    execute_moderation,
    RestoreBackupView,
)

# Configurar logging detallado
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("DiscordAISentinel")

# Intents necesarios para moderación avanzada y lectura de contenido
intents = discord.Intents.default()
intents.message_content = True  # Message Content Intent (Activo en portal de desarrolladores)
intents.members = True          # Para calcular antigüedad y aplicar timeouts
intents.guilds = True

bot = commands.Bot(command_prefix=["!", "/"], intents=intents, help_command=None)


# ==============================================================================
# EVENTO ON_READY (INICIALIZACIÓN Y CHEQUEO DE PERMISOS)
# ==============================================================================
@bot.event
async def on_ready():
    logger.info("=" * 60)
    logger.info(f"🛡️  DISCORD AI SENTINEL EN LÍNEA")
    logger.info(f"   Usuario: {bot.user} (ID: {bot.user.id})")
    active_model = settings.OPENROUTER_MODEL if settings.OPENROUTER_API_KEY else settings.GEMINI_MODEL
    logger.info(f"   Modelo IA: {active_model}")
    logger.info(f"   Roles en Whitelist: {', '.join(settings.whitelisted_roles_set)}")
    logger.info(f"   Servidores activos: {len(bot.guilds)}")
    logger.info("=" * 60)

    # Sincronizar slash commands directamente en cada servidor para que aparezcan al instante (0 delay)
    for guild in bot.guilds:
        me = guild.me
        can_manage_msgs = me.guild_permissions.manage_messages
        can_moderate = me.guild_permissions.moderate_members
        logger.info(
            f"   - Gremio: '{guild.name}' | Manage Messages: {'✅' if can_manage_msgs else '❌'} | "
            f"Moderate Members (Timeouts): {'✅' if can_moderate else '❌'}"
        )
        try:
            bot.tree.copy_global_to(guild=guild)
            synced = await bot.tree.sync(guild=guild)
            logger.info(f"✅ Sincronizados {len(synced)} comandos instantáneos en '{guild.name}'.")
        except Exception as e:
            logger.error(f"❌ Error al sincronizar en '{guild.name}': {e}")


# ==============================================================================
# EVENTO ON_MESSAGE (PIPELINE DE SEGURIDAD EN TIEMPO REAL)
# ==============================================================================
@bot.event
async def on_message(message: discord.Message):
    # Ignorar mensajes del propio bot
    if message.author == bot.user:
        return

    # Solo procesar en canales de texto de servidores
    if not message.guild:
        return

    # 1. Regla 0: Whitelist por Roles o Permisos
    is_trusted, trust_reason = is_author_whitelisted(message)
    if is_trusted:
        await bot.process_commands(message)
        return

    # 2. Extracción de Metadatos (Antigüedad / Webhook)
    is_webhook = bool(message.webhook_id)
    account_age = get_account_age_days(message.author) if not is_webhook else 0
    mentions_count = len(message.mentions)

    # 3. Pre-filtrado Heurístico (Evita saturación de API y latencia)
    flagged, filter_reason = should_inspect(
        content=message.content,
        is_webhook=is_webhook,
        mentions_count=mentions_count,
    )

    if not flagged:
        # Tráfico seguro: procesar comandos si aplica y salir
        await bot.process_commands(message)
        return

    logger.info(f"🔍 Mensaje sospechoso detectado. Motivo pre-filtro: '{filter_reason}'. Evaluando con IA...")

    # 4. Auditoría On-Chain pasiva (Si contiene dirección de Solana)
    on_chain_data = await scan_solana_threats(message.content)

    author_info = (
        f"Tipo: {'WEBHOOK COMPROMETIDO (Simulado o real)' if is_webhook else 'Usuario Normal'}\n"
        f"Nombre: {message.author.display_name}\n"
        f"Antigüedad de cuenta: {account_age} días\n"
        f"Canal: #{message.channel.name}"
    )
    if on_chain_data and on_chain_data.get("detected"):
        author_info += (
            f"\n--- AUDITORÍA ON-CHAIN SOLANA ---\n"
            f"Dirección: {on_chain_data['address']}\n"
            f"Saldo: {on_chain_data.get('balance_sol')} SOL\n"
            f"Riesgo On-Chain: {on_chain_data.get('risk_assessment')}"
        )

    # 5. Clasificación Semántica con Gemini Flash
    ai_result = await analyze_semantic_intent(
        text=message.content,
        author_metadata=author_info,
    )

    logger.info(
        f"📊 Veredicto IA: Malicioso={ai_result.get('is_malicious')} | "
        f"Confianza={ai_result.get('confidence')} | Vector={ai_result.get('attack_vector')} | "
        f"Latencia={ai_result.get('latency_ms')}ms"
    )

    # 6. Ejecución de la Acción Gradual con datos on-chain
    await execute_moderation(
        bot=bot,
        message=message,
        ai_result=ai_result,
        is_webhook=is_webhook,
        account_age=account_age,
        on_chain_data=on_chain_data,
    )

    # Procesar comandos regulares
    await bot.process_commands(message)


# ==============================================================================
# SLASH COMMANDS PARA JUECES, ADMINISTRADORES Y DEMOS
# ==============================================================================
@bot.tree.command(name="sentinel-status", description="Muestra el estado operativo del bot de seguridad IA.")
async def sentinel_status(interaction: discord.Interaction):
    embed = discord.Embed(
        title="🛡️ Estado de Discord AI Sentinel",
        color=discord.Color.blue(),
    )
    active_provider = f"OpenRouter ({settings.OPENROUTER_MODEL})" if settings.OPENROUTER_API_KEY else f"Gemini Native ({settings.GEMINI_MODEL})"
    embed.add_field(name="Motor de IA", value=f"`{active_provider}`", inline=False)
    embed.add_field(name="Canal de Moderación", value=f"<#{settings.MOD_LOG_CHANNEL_ID}>" if settings.MOD_LOG_CHANNEL_ID else "No asignado", inline=True)
    embed.add_field(name="Umbral Nivel 1 (Alerta)", value=f"{settings.THRESHOLD_LEVEL_1_ALERT * 100:.0f}%", inline=True)
    embed.add_field(name="Umbral Nivel 2 (Acción)", value=f"{settings.THRESHOLD_LEVEL_2_ACTION * 100:.0f}%", inline=True)
    embed.add_field(name="Antigüedad de Confianza", value=f"> {settings.ACCOUNT_SAFE_AGE_DAYS} días", inline=True)
    embed.add_field(name="Servidores Conectados", value=str(len(bot.guilds)), inline=True)
    embed.set_footer(text="Desarrollado para Superteam Earn | Security & AI Agents")
    await interaction.response.send_message(embed=embed, ephemeral=True)


@bot.tree.command(name="sentinel-setchannel", description="Establece el canal actual para recibir alertas y reportes de seguridad.")
async def sentinel_setchannel(interaction: discord.Interaction):
    if not interaction.user.guild_permissions.administrator:
        await interaction.response.send_message("❌ Solo los administradores pueden configurar el canal de seguridad.", ephemeral=True)
        return

    settings.MOD_LOG_CHANNEL_ID = interaction.channel_id
    try:
        env_path = os.path.join(os.path.dirname(__file__), ".env")
        if os.path.exists(env_path):
            with open(env_path, "r", encoding="utf-8") as f:
                content = f.read()
            new_content = re.sub(r"MOD_LOG_CHANNEL_ID=\d*", f"MOD_LOG_CHANNEL_ID={interaction.channel_id}", content)
            with open(env_path, "w", encoding="utf-8") as f:
                f.write(new_content)
    except Exception as e:
        logger.error(f"Error guardando MOD_LOG_CHANNEL_ID: {e}")

    embed = discord.Embed(
        title="✅ Canal de Seguridad Configurado",
        description=f"A partir de ahora, todas las alertas, detecciones de phishing y reportes de seguridad se enviarán a <#{interaction.channel_id}>.",
        color=discord.Color.green(),
    )
    await interaction.response.send_message(embed=embed)


@bot.tree.command(name="sentinel-test", description="Prueba el análisis semántico de un texto sin disparar moderación.")
@app_commands.describe(texto="Texto sospechoso a evaluar")
async def sentinel_test(interaction: discord.Interaction, texto: str):
    await interaction.response.defer(ephemeral=True)

    result = await analyze_semantic_intent(
        text=texto,
        author_metadata=f"Simulación por Admin: {interaction.user.display_name}",
    )

    is_mal = result.get("is_malicious", False)
    conf = result.get("confidence", 0.0)
    color = discord.Color.red() if is_mal else discord.Color.green()

    embed = discord.Embed(
        title="🧪 Resultado del Test Semántico IA",
        color=color,
    )
    embed.add_field(name="¿Es Malicioso?", value="🚨 SÍ" if is_mal else "✅ NO", inline=True)
    embed.add_field(name="Confianza", value=f"**{conf * 100:.1f}%**", inline=True)
    embed.add_field(name="Vector", value=f"`{result.get('attack_vector')}`", inline=True)
    embed.add_field(name="Latencia Motor", value=f"{result.get('latency_ms')} ms", inline=True)
    embed.add_field(name="Diagnóstico", value=result.get("reason", "Sin diagnóstico"), inline=False)
    embed.add_field(name="Texto Evaluado", value=f"```{texto[:500]}```", inline=False)

    await interaction.followup.send(embed=embed, ephemeral=True)


# ==============================================================================
# COMANDOS DE TEXTO DIRECTO (Prefijo !) - Funcionan al instante
# ==============================================================================
@bot.command(name="status")
async def cmd_status(ctx: commands.Context):
    """Muestra el estado con !status"""
    embed = discord.Embed(
        title="🛡️ Estado de Discord AI Sentinel",
        color=discord.Color.blue(),
    )
    active_provider = f"OpenRouter ({settings.OPENROUTER_MODEL})" if settings.OPENROUTER_API_KEY else f"Gemini Native ({settings.GEMINI_MODEL})"
    embed.add_field(name="Motor de IA", value=f"`{active_provider}`", inline=False)
    embed.add_field(name="Canal de Moderación", value=f"<#{settings.MOD_LOG_CHANNEL_ID}>" if settings.MOD_LOG_CHANNEL_ID else "No asignado", inline=True)
    embed.add_field(name="Umbral Nivel 1 (Alerta)", value=f"{settings.THRESHOLD_LEVEL_1_ALERT * 100:.0f}%", inline=True)
    embed.add_field(name="Umbral Nivel 2 (Acción)", value=f"{settings.THRESHOLD_LEVEL_2_ACTION * 100:.0f}%", inline=True)
    embed.add_field(name="Antigüedad de Confianza", value=f"> {settings.ACCOUNT_SAFE_AGE_DAYS} días", inline=True)
    embed.add_field(name="Servidores Conectados", value=str(len(bot.guilds)), inline=True)
    embed.set_footer(text="Desarrollado para Superteam Earn | Security & AI Agents")
    await ctx.send(embed=embed)


@bot.command(name="setchannel")
async def cmd_setchannel(ctx: commands.Context):
    """Configura el canal actual con !setchannel"""
    if not ctx.author.guild_permissions.administrator:
        await ctx.send("❌ Solo los administradores pueden configurar el canal de seguridad.")
        return

    settings.MOD_LOG_CHANNEL_ID = ctx.channel.id
    try:
        env_path = os.path.join(os.path.dirname(__file__), ".env")
        if os.path.exists(env_path):
            with open(env_path, "r", encoding="utf-8") as f:
                content = f.read()
            new_content = re.sub(r"MOD_LOG_CHANNEL_ID=\d*", f"MOD_LOG_CHANNEL_ID={ctx.channel.id}", content)
            with open(env_path, "w", encoding="utf-8") as f:
                f.write(new_content)
    except Exception as e:
        logger.error(f"Error guardando MOD_LOG_CHANNEL_ID: {e}")

    embed = discord.Embed(
        title="✅ Canal de Seguridad Configurado",
        description=f"A partir de ahora, todas las alertas, detecciones de phishing y reportes de seguridad se enviarán a <#{ctx.channel.id}>.",
        color=discord.Color.green(),
    )
    await ctx.send(embed=embed)


@bot.command(name="test")
async def cmd_test(ctx: commands.Context, *, texto: str):
    """Evalúa un texto sospechoso con !test <texto>"""
    async with ctx.typing():
        on_chain_data = await scan_solana_threats(texto)
        author_info = f"Test manual por Admin: {ctx.author.display_name}"
        if on_chain_data and on_chain_data.get("detected"):
            author_info += f"\nOn-Chain Solana: {on_chain_data['address']} (Saldo: {on_chain_data.get('balance_sol')} SOL, Riesgo: {on_chain_data.get('risk_assessment')})"

        result = await analyze_semantic_intent(
            text=texto,
            author_metadata=author_info,
        )

    is_mal = result.get("is_malicious", False)
    conf = result.get("confidence", 0.0)
    color = discord.Color.red() if is_mal else discord.Color.green()

    embed = discord.Embed(
        title="🧪 Resultado del Test Semántico IA",
        color=color,
    )
    embed.add_field(name="¿Es Malicioso?", value="🚨 SÍ" if is_mal else "✅ NO", inline=True)
    embed.add_field(name="Confianza", value=f"**{conf * 100:.1f}%**", inline=True)
    embed.add_field(name="Vector", value=f"`{result.get('attack_vector')}`", inline=True)
    embed.add_field(name="Latencia Motor", value=f"{result.get('latency_ms')} ms", inline=True)

    if on_chain_data and on_chain_data.get("detected"):
        embed.add_field(
            name="⛓️ Auditoría On-Chain Solana",
            value=(
                f"• Dirección: `{on_chain_data['address'][:8]}...{on_chain_data['address'][-6:]}`\n"
                f"• Saldo: `{on_chain_data.get('balance_sol', 0)} SOL`\n"
                f"• Riesgo On-Chain: **{on_chain_data.get('risk_assessment')}**"
            ),
            inline=False,
        )

    embed.add_field(name="Diagnóstico", value=result.get("reason", "Sin diagnóstico"), inline=False)
    embed.add_field(name="Texto Evaluado", value=f"```{texto[:500]}```", inline=False)

    await ctx.send(embed=embed)


@bot.command(name="simular")
async def cmd_simular(ctx: commands.Context):
    """Simula una alerta de ataque crítica en el canal de seguridad configurado con botón interactivo."""
    log_channel = bot.get_channel(settings.MOD_LOG_CHANNEL_ID) if settings.MOD_LOG_CHANNEL_ID else ctx.channel
    if not log_channel:
        await ctx.send("❌ No se encontró el canal de alertas configurado.")
        return

    sample_scam = "@everyone ¡URGENTE! Airdrop sorpresa oficial de Solana de $2,500 USDC para los primeros 50 usuarios: https://solana-claim-airdrop-drainer.xyz"

    embed = discord.Embed(
        title="🛡️ Amenaza Crítica Neutralizada (Auto-Mod)",
        color=discord.Color.red(),
        timestamp=datetime.now(timezone.utc),
    )
    embed.add_field(name="Origen de la Amenaza", value="🚨 **WEBHOOK COMPROMETIDO (Simulado)**: `AnnouncementsBot`", inline=True)
    embed.add_field(name="Vector Detectado", value="`AIRDROP_SCAM`", inline=True)
    embed.add_field(name="Confianza IA", value="**99.0%** (OpenRouter / Gemini Flash)", inline=True)
    embed.add_field(name="Canal de Ataque", value=ctx.channel.mention, inline=True)
    embed.add_field(name="Tiempo de Reacción", value="340 ms", inline=True)
    embed.add_field(name="Acción Aplicada", value="Borrado preventivo + Timeout 10m", inline=True)
    embed.add_field(
        name="⛓️ Auditoría On-Chain Solana (Mainnet)",
        value="• Billetera de Drenador: `7xKXtg2C...s45Y`\n• Saldo: `0.0 SOL` (Fondos extraídos al instante)\n• Diagnóstico On-Chain: **ALTO (Billetera nueva / Desechable)**",
        inline=False,
    )
    embed.add_field(name="Diagnóstico Técnico", value="Ingeniería social agresiva con mención global (@everyone), urgencia artificial y redirección a dominio malicioso (.xyz) típico de drenadores de billeteras Solana.", inline=False)
    embed.add_field(name="Copia de Seguridad del Mensaje", value=f"```{sample_scam}```", inline=False)
    embed.set_footer(text="Si fue un falso positivo, cualquier moderador puede restaurarlo abajo ⬇️")

    restore_view = RestoreBackupView(
        channel_id=ctx.channel.id,
        original_text=sample_scam,
        author_mention=ctx.author.mention,
    )
    await log_channel.send(embed=embed, view=restore_view)
    if log_channel.id != ctx.channel.id:
        await ctx.send(f"🚨 Alerta enviada a <#{log_channel.id}> con botón de restauración.")


# ==============================================================================
# EJECUCIÓN PRINCIPAL
# ==============================================================================
if __name__ == "__main__":
    if not settings.DISCORD_BOT_TOKEN:
        logger.error("❌ ERROR: DISCORD_BOT_TOKEN no configurado en el archivo .env")
        logger.info("Por favor, abre C:\\Users\\luis\\discord_mod\\.env y coloca tu token.")
        sys.exit(1)

    logger.info("Iniciando conexión con Gateway de Discord...")
    bot.run(settings.DISCORD_BOT_TOKEN)

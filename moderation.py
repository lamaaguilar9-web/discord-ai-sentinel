import discord
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

from config import settings


def get_account_age_days(user: discord.User | discord.Member) -> int:
    """Calcula la antigüedad de la cuenta del usuario en días."""
    if not user.created_at:
        return 0
    now = datetime.now(timezone.utc)
    return (now - user.created_at).days


def is_author_whitelisted(message: discord.Message) -> Tuple[bool, str]:
    """
    Evalúa la lista blanca por roles y permisos.
    Regla de oro: Los Webhooks NUNCA están en la lista blanca por roles.
    """
    if message.webhook_id:
        return False, "Mensaje proveniente de un Webhook (No aplica whitelist de roles)"

    member = message.author
    if not isinstance(member, discord.Member):
        return False, "Usuario fuera del contexto de servidor (DM o no miembro)"

    # 1. Permisos nativos de Discord (Administrador o Moderador con Manage Messages)
    if member.guild_permissions.administrator:
        return True, "Permiso nativo de Administrador"
    if member.guild_permissions.manage_messages or member.guild_permissions.moderate_members:
        return True, "Permiso nativo de Moderador"

    # 2. Whitelist por Roles
    author_roles = {r.name.strip().lower() for r in member.roles}
    matched_roles = author_roles.intersection(settings.whitelisted_roles_set)
    if matched_roles:
        return True, f"Rol de confianza asignado: {', '.join(matched_roles)}"

    return False, "Usuario estándar (Sujeto a filtrado de seguridad)"


# ==============================================================================
# VISTAS INTERACTIVAS CON BOTONES (Human-in-the-Loop)
# ==============================================================================

class Level1AlertView(discord.ui.View):
    """
    Vista interactiva para sospechas intermedias (Nivel 1: Confianza 0.70 a 0.84).
    Permite al moderador humano decidir en 1 clic sin borrar mensajes legítimos.
    """
    def __init__(self, target_message: discord.Message, author_id: int, reason: str):
        super().__init__(timeout=86400)  # 24 horas activo
        self.target_message = target_message
        self.author_id = author_id
        self.reason = reason

    @discord.ui.button(label="Borrar y Timeout (10m)", style=discord.ButtonStyle.danger, emoji="🔨")
    async def delete_and_mute(self, interaction: discord.Interaction, button: discord.ui.Button):
        try:
            await self.target_message.delete()
            guild = self.target_message.guild
            if guild:
                member = guild.get_member(self.author_id)
                if member:
                    await member.timeout(timedelta(minutes=10), reason=f"Mod Humano: {self.reason}")
            
            # Desactivar botones después de actuar
            for child in self.children:
                child.disabled = True
            await interaction.response.edit_message(
                content=f"✅ **Acción ejecutada por {interaction.user.mention}:** Mensaje borrado y usuario aislado 10 min.",
                view=self
            )
            self.stop()
        except discord.NotFound:
            await interaction.response.send_message("⚠️ El mensaje ya había sido borrado.", ephemeral=True)
        except Exception as e:
            await interaction.response.send_message(f"❌ Error al ejecutar acción: {e}", ephemeral=True)

    @discord.ui.button(label="Falso Positivo (Descartar)", style=discord.ButtonStyle.secondary, emoji="🛡️")
    async def dismiss(self, interaction: discord.Interaction, button: discord.ui.Button):
        for child in self.children:
            child.disabled = True
        await interaction.response.edit_message(
            content=f"⚪ **Alerta descartada por {interaction.user.mention}** (Marcado como legítimo).",
            view=self
        )
        self.stop()


class RestoreBackupView(discord.ui.View):
    """
    Vista para Nivel 2 (Borrado automático >= 0.85).
    Garantía de seguridad: Si el borrado automático fue un error, un moderador
    puede presionar un solo botón y restaurar el mensaje inmediatamente.
    """
    def __init__(self, channel_id: int, original_text: str, author_mention: str):
        super().__init__(timeout=86400)
        self.channel_id = channel_id
        self.original_text = original_text
        self.author_mention = author_mention

    @discord.ui.button(label="Restaurar Mensaje (Rollback)", style=discord.ButtonStyle.success, emoji="🔄")
    async def restore(self, interaction: discord.Interaction, button: discord.ui.Button):
        guild = interaction.guild
        channel = guild.get_channel(self.channel_id) if guild else None
        if channel and hasattr(channel, "send"):
            await channel.send(
                f"*(Mensaje de {self.author_mention} restaurado por {interaction.user.mention} tras revisión):*\n"
                f">>> {self.original_text}"
            )
            for child in self.children:
                child.disabled = True
            await interaction.response.edit_message(
                content=f"✅ **Mensaje restaurado exitosamente en <#{self.channel_id}>.**",
                view=self
            )
            self.stop()
        else:
            await interaction.response.send_message("❌ No se pudo encontrar el canal original.", ephemeral=True)


# ==============================================================================
# EJECUTOR CENTRAL DE MODERACIÓN
# ==============================================================================

async def execute_moderation(
    bot: discord.Client,
    message: discord.Message,
    ai_result: dict,
    is_webhook: bool,
    account_age: int,
    on_chain_data: Optional[dict] = None,
):
    """Ejecuta la política de acción gradual con logging detallado."""
    confidence = ai_result.get("confidence", 0.0)
    is_malicious = ai_result.get("is_malicious", False)
    reason = ai_result.get("reason", "Actividad no permitida")
    attack_vector = ai_result.get("attack_vector", "SUSPICIOUS")
    latency_ms = ai_result.get("latency_ms", 0.0)

    # Si la cuenta tiene más de 30 días y NO es webhook, exigimos 0.90 para borrado automático
    effective_threshold_action = (
        0.90 if (account_age > settings.ACCOUNT_SAFE_AGE_DAYS and not is_webhook)
        else settings.THRESHOLD_LEVEL_2_ACTION
    )

    log_channel = bot.get_channel(settings.MOD_LOG_CHANNEL_ID) if settings.MOD_LOG_CHANNEL_ID else None

    # --------------------------------------------------------------------------
    # NIVEL 1: Sospecha Media (0.70 a 0.84) -> Alerta con botones sin borrar
    # --------------------------------------------------------------------------
    if is_malicious and settings.THRESHOLD_LEVEL_1_ALERT <= confidence < effective_threshold_action:
        if log_channel and hasattr(log_channel, "send"):
            embed = discord.Embed(
                title="⚠️ Sospecha Media Detectada (Revisión Humana Requerida)",
                color=discord.Color.gold(),
                timestamp=datetime.now(timezone.utc),
            )
            embed.add_field(name="Autor", value=f"{message.author.mention} (`{message.author.id}`)", inline=True)
            embed.add_field(name="¿Es Webhook?", value="🚨 Sí (Compromiso potencial)" if is_webhook else "No", inline=True)
            embed.add_field(name="Antigüedad Cuenta", value=f"{account_age} días", inline=True)
            embed.add_field(name="Vector de Ataque", value=f"`{attack_vector}`", inline=True)
            embed.add_field(name="Confianza IA", value=f"**{confidence * 100:.1f}%**", inline=True)
            embed.add_field(name="Latencia Motor", value=f"{latency_ms} ms", inline=True)
            if on_chain_data and on_chain_data.get("detected"):
                embed.add_field(
                    name="⛓️ Auditoría On-Chain Solana",
                    value=(
                        f"• Dirección: `{on_chain_data['address'][:8]}...{on_chain_data['address'][-6:]}`\n"
                        f"• Saldo: `{on_chain_data.get('balance_sol', 0)} SOL` | Red: `{on_chain_data.get('network', 'Solana')}`\n"
                        f"• Riesgo On-Chain: **{on_chain_data.get('risk_assessment')}**"
                    ),
                    inline=False,
                )

            embed.add_field(name="Canal", value=message.channel.mention, inline=True)
            embed.add_field(name="Diagnóstico IA", value=reason, inline=False)
            embed.add_field(name="Contenido del Mensaje", value=f"```{message.content[:700]}```", inline=False)
            embed.set_footer(text="Política: Nivel 1 (Mensaje conservado a la espera de decisión humana)")

            view = Level1AlertView(
                target_message=message,
                author_id=message.author.id,
                reason=reason,
            )
            await log_channel.send(embed=embed, view=view)

    # --------------------------------------------------------------------------
    # NIVEL 2: Sospecha Alta (>= 0.85) -> Borrado + Timeout 10 min + Log con Rollback
    # --------------------------------------------------------------------------
    elif is_malicious and confidence >= effective_threshold_action:
        original_content = message.content
        channel_id = message.channel.id

        # A) Borrado preventivo
        try:
            await message.delete()
        except (discord.NotFound, discord.Forbidden):
            pass

        # B) Timeout preventivo de 10 minutos (solo si es miembro y no webhook)
        timeout_applied = False
        if not is_webhook and isinstance(message.author, discord.Member):
            try:
                await message.author.timeout(
                    timedelta(minutes=10),
                    reason=f"AI Sentinel Guard: {reason} [{attack_vector}]"
                )
                timeout_applied = True
            except discord.Forbidden:
                pass  # Jerarquía de roles en Discord

        # C) Log estructurado con botón de Rollback
        if log_channel and hasattr(log_channel, "send"):
            embed = discord.Embed(
                title="🛡️ Amenaza Crítica Neutralizada (Auto-Mod)",
                color=discord.Color.red(),
                timestamp=datetime.now(timezone.utc),
            )
            author_desc = (
                f"🚨 **WEBHOOK COMPROMETIDO**: `{message.author.name}`"
                if is_webhook
                else f"{message.author.mention} (`{message.author.id}`)"
            )
            embed.add_field(name="Origen de la Amenaza", value=author_desc, inline=True)
            embed.add_field(name="Vector Detectado", value=f"`{attack_vector}`", inline=True)
            embed.add_field(name="Confianza IA", value=f"**{confidence * 100:.1f}%**", inline=True)
            embed.add_field(name="Canal Afectado", value=f"<#{channel_id}>", inline=True)
            embed.add_field(name="Tiempo de Reacción", value=f"{latency_ms} ms", inline=True)
            embed.add_field(name="Acción Aplicada", value="Borrado preventivo + Timeout 10m" if timeout_applied else "Mensaje borrado", inline=True)

            if on_chain_data and on_chain_data.get("detected"):
                embed.add_field(
                    name="⛓️ Auditoría On-Chain Solana (Mainnet)",
                    value=(
                        f"• Dirección: `{on_chain_data['address'][:8]}...{on_chain_data['address'][-6:]}`\n"
                        f"• Saldo: `{on_chain_data.get('balance_sol', 0)} SOL` | Red: `{on_chain_data.get('network', 'Solana')}`\n"
                        f"• Diagnóstico On-Chain: **{on_chain_data.get('risk_assessment')}**"
                    ),
                    inline=False,
                )

            embed.add_field(name="Diagnóstico Técnico", value=reason, inline=False)
            embed.add_field(name="Copia de Seguridad del Mensaje", value=f"```{original_content[:800]}```", inline=False)
            embed.set_footer(text="Si fue un falso positivo, cualquier moderador puede restaurarlo abajo ⬇️")

            restore_view = RestoreBackupView(
                channel_id=channel_id,
                original_text=original_content,
                author_mention=message.author.mention,
            )
            await log_channel.send(embed=embed, view=restore_view)

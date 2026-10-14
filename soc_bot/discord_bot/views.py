from __future__ import annotations

import discord


class ConfirmView(discord.ui.View):
    """Confirm/Cancel buttons that only the requesting analyst can press."""

    def __init__(self, author_id: int, timeout: float = 60):
        super().__init__(timeout=timeout)
        self.author_id = author_id
        self.confirmed = False

    async def ask(self) -> bool:
        await self.wait()
        return self.confirmed

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id != self.author_id:
            await interaction.response.send_message(
                "Only the analyst who issued this command can confirm it.", ephemeral=True
            )
            return False
        return True

    @discord.ui.button(label="Confirm", style=discord.ButtonStyle.danger)
    async def confirm(self, interaction: discord.Interaction, _: discord.ui.Button) -> None:
        self.confirmed = True
        await interaction.response.defer()
        self.stop()

    @discord.ui.button(label="Cancel", style=discord.ButtonStyle.secondary)
    async def cancel(self, interaction: discord.Interaction, _: discord.ui.Button) -> None:
        await interaction.response.defer()
        self.stop()

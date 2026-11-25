"""Keyboard regressions for the optional fixed-screen presentation."""

from importlib.util import find_spec
import unittest


@unittest.skipUnless(find_spec("textual"), "Optional Textual presentation is not installed.")
class TestPanelTUI(unittest.IsolatedAsyncioTestCase):
    async def test_focus_and_tabs(self):
        from pgopcore.panel_tui import FixedPanel, Question
        from textual.widgets import Button, ContentSwitcher, Input, OptionList, Static, Tab

        app = FixedPanel()
        async with app.run_test(size=(60, 20)) as pilot:
            tabs = app.query_one(ContentSwitcher)
            await pilot.press("2", "down")
            self.assertEqual(tabs.current, "files")
            self.assertEqual(app.query_one("#tab-files", Tab).label_text, "[2 Archivos]")
            choices = app.query_one("#files OptionList", OptionList)
            self.assertEqual(choices.highlighted, 1)
            self.assertTrue(choices.get_option_at_index(1).prompt.plain.startswith("> "))

            await pilot.press("3", "4", "5", "2")
            self.assertEqual(tabs.current, "files")
            self.assertEqual(choices.highlighted, 1)
            await pilot.press("A")
            await pilot.pause()
            self.assertIsInstance(app.screen, Question)
            await pilot.press("C", "2", "0", "2", "5")
            self.assertEqual(app.screen.query_one(Input).value, "C2025")
            self.assertEqual(tabs.current, "files")

            await pilot.press("escape")
            await pilot.pause()
            self.assertIs(app.screen, app.main_screen)
            await pilot.press("0", "0")
            self.assertEqual(tabs.current, "home")
            self.assertEqual(app.screen.focused.id, "no")
            self.assertEqual(app.screen.query_one("#no", Button).label.plain, "> Cancelar")
            await pilot.press("enter")
            self.assertEqual(app.query_one("#state", Static).content, "Salida cancelada.")
            await pilot.press("0")
            await pilot.press("0")
            self.assertIs(app.screen, app.main_screen)

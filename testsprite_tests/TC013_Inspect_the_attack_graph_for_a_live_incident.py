import asyncio
import re
from playwright import async_api
from playwright.async_api import expect

async def run_test():
    pw = None
    browser = None
    context = None

    try:
        # Start a Playwright session in asynchronous mode
        pw = await async_api.async_playwright().start()

        # Launch a Chromium browser in headless mode with custom arguments
        browser = await pw.chromium.launch(
            headless=True,
            args=[
                "--window-size=1280,720",
                "--disable-dev-shm-usage",
                "--ipc=host",
                "--single-process"
            ],
        )

        # Create a new browser context (like an incognito window)
        context = await browser.new_context()
        # Wider default timeout to match the agent's DOM-stability budget;
        # auto-waiting Playwright APIs (expect, locator.wait_for) inherit this.
        context.set_default_timeout(15000)

        # Open a new page in the browser context
        page = await context.new_page()

        # Interact with the page elements to simulate user flow
        # -> navigate
        await page.goto("http://localhost:5173")
        try:
            await page.wait_for_load_state("domcontentloaded", timeout=5000)
        except Exception:
            pass
        
        # -> Click the visible 'Enter demo environment' button to open the demo Analyze area.
        # Enter demo environment button
        elem = page.get_by_role('button', name='Enter demo environment', exact=True)
        await elem.click(timeout=10000)
        
        # -> Click the 'Analyze' button for the 'LANL red-team campaign — all 104 accounts' scenario to start live analysis.
        # Analyze button
        elem = page.locator('xpath=/html/body/div/div/div/div[2]/div[2]/section/div[2]/div[3]/button')
        await elem.click(timeout=10000)
        
        # -> Click the 'Attack Graph' link in the left navigation to open the Attack Graph page.
        # Attack Graph link
        elem = page.get_by_role('link', name='Attack Graph', exact=True)
        await elem.click(timeout=10000)
        
        # -> Click the host 'C17693' in the Hosts list to open its authentication/evidence details.
        # C17693 pivot 463 button
        elem = page.get_by_role('button', name='C17693 pivot 463', exact=True)
        await elem.click(timeout=10000)
        
        # --> Assertions to verify final state
        
        # --> Verify the attack graph is displayed
        await page.locator("xpath=/html/body/div[1]/div/div/div[2]/div/section/div[2]/div/div/canvas").nth(0).scroll_into_view_if_needed()
        # Assert: Attack-path graph canvas is visible on the page.
        await expect(page.locator("xpath=/html/body/div[1]/div/div/div[2]/div/section/div[2]/div/div/canvas").nth(0)).to_be_visible(timeout=15000), "Attack-path graph canvas is visible on the page."
        await page.locator("xpath=/html/body/div[1]/div/div/div[2]/div/section/div[2]/div/div").nth(0).scroll_into_view_if_needed()
        # Assert: Attack graph container div is visible, confirming the graph area is displayed.
        await expect(page.locator("xpath=/html/body/div[1]/div/div/div[2]/div/section/div[2]/div/div").nth(0)).to_be_visible(timeout=15000), "Attack graph container div is visible, confirming the graph area is displayed."
        
        # --> Verify host relationship evidence is visible
        # Assert: Host detail panel titled 'C17693' is visible.
        await expect(page.locator("xpath=/html/body/div[1]/div/div/div[2]/div/div/section[1]/div[1]/h3/span").nth(0)).to_have_text("C17693", timeout=15000), "Host detail panel titled 'C17693' is visible."
        # Assert: Host relationship list shows a moved-to host 'C1759', confirming relationship evidence is present.
        await expect(page.locator("xpath=/html/body/div[1]/div/div/div[2]/div/div/section[1]/div[4]/button[1]").nth(0)).to_contain_text("C1759", timeout=15000), "Host relationship list shows a moved-to host 'C1759', confirming relationship evidence is present."
        await asyncio.sleep(5)

    finally:
        if context:
            await context.close()
        if browser:
            await browser.close()
        if pw:
            await pw.stop()

asyncio.run(run_test())
    
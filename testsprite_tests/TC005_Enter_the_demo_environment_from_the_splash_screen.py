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
        
        # -> Click the 'Enter demo environment' button on the landing page to enter the demo environment and reach the analysis area.
        # Enter demo environment button
        elem = page.get_by_role('button', name='Enter demo environment', exact=True)
        await elem.click(timeout=10000)
        
        # --> Assertions to verify final state
        
        # --> Verify the analysis screen is displayed
        # Assert: The current URL contains 'analyze', indicating the analysis screen is displayed.
        await expect(page).to_have_url(re.compile("analyze"), timeout=15000), "The current URL contains 'analyze', indicating the analysis screen is displayed."
        # Assert: The 'Analyze Log' navigation item is visible in the sidebar.
        await expect(page.locator("xpath=/html/body/div[1]/div/aside/nav[1]/a[1]").nth(0)).to_have_text("Analyze Log", timeout=15000), "The 'Analyze Log' navigation item is visible in the sidebar."
        # Assert: An 'Analyze' scenario button is visible on the analysis screen.
        await expect(page.locator("xpath=/html/body/div[1]/div/div/div[2]/div[2]/section/div[2]/div[1]/button").nth(0)).to_have_text("Analyze", timeout=15000), "An 'Analyze' scenario button is visible on the analysis screen."
        await asyncio.sleep(5)

    finally:
        if context:
            await context.close()
        if browser:
            await browser.close()
        if pw:
            await pw.stop()

asyncio.run(run_test())
    
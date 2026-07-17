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
        
        # -> Click the 'Enter demo environment' button on the splash card to enter the demo environment.
        # Enter demo environment button
        elem = page.get_by_role('button', name='Enter demo environment', exact=True)
        await elem.click(timeout=10000)
        
        # --> Assertions to verify final state
        
        # --> Verify the analysis page is displayed
        # Assert: The URL contains '/analyze', confirming the analysis page is loaded.
        await expect(page).to_have_url(re.compile("/analyze"), timeout=15000), "The URL contains '/analyze', confirming the analysis page is loaded."
        await page.locator("xpath=/html/body/div/div/aside/nav[1]/a[1]").nth(0).scroll_into_view_if_needed()
        # Assert: The 'Analyze Log' navigation link is visible on the analysis page.
        await expect(page.locator("xpath=/html/body/div/div/aside/nav[1]/a[1]").nth(0)).to_be_visible(timeout=15000), "The 'Analyze Log' navigation link is visible on the analysis page."
        await page.locator("xpath=/html/body/div/div/div/div[2]/div[2]/section/div[2]/div[1]/button").nth(0).scroll_into_view_if_needed()
        # Assert: An 'Analyze' button is visible on the analysis page.
        await expect(page.locator("xpath=/html/body/div/div/div/div[2]/div[2]/section/div[2]/div[1]/button").nth(0)).to_be_visible(timeout=15000), "An 'Analyze' button is visible on the analysis page."
        await asyncio.sleep(5)

    finally:
        if context:
            await context.close()
        if browser:
            await browser.close()
        if pw:
            await pw.stop()

asyncio.run(run_test())
    
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
        
        # -> Open the Analyze page by navigating to /analyze (go to the 'Analyze' view).
        await page.goto("http://localhost:5173/analyze")
        try:
            await page.wait_for_load_state("domcontentloaded", timeout=5000)
        except Exception:
            pass
        
        # -> Click the 'Analyze' button on the 'LANL red-team campaign — all 104 accounts (real)' scenario to start the live pipeline.
        # Analyze button
        elem = page.locator('xpath=/html/body/div/div/div/div[2]/div[2]/section/div[2]/div[3]/button')
        await elem.click(timeout=10000)
        
        # --> Assertions to verify final state
        
        # --> Verify the live analysis overview is displayed
        # Assert: The browser is on the Overview page (URL contains /overview).
        await expect(page).to_have_url(re.compile("/overview"), timeout=15000), "The browser is on the Overview page (URL contains /overview)."
        # Assert: The Overview page shows the MTTD metric, indicating live analysis content is displayed.
        await expect(page.locator("xpath=/html/body/div[1]/div/div/div[2]/section[1]/div[1]/span[2]").nth(0)).to_contain_text("MTTD", timeout=15000), "The Overview page shows the MTTD metric, indicating live analysis content is displayed."
        await asyncio.sleep(5)

    finally:
        if context:
            await context.close()
        if browser:
            await browser.close()
        if pw:
            await pw.stop()

asyncio.run(run_test())
    
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
        
        # -> Click the 'Enter demo environment' button to enter the demo environment.
        # Enter demo environment button
        elem = page.get_by_role('button', name='Enter demo environment', exact=True)
        await elem.click(timeout=10000)
        
        # -> Click the 'Analyze' button on the "LANL red-team campaign — all 104 accounts" scenario to start the analysis pipeline.
        # Analyze button
        elem = page.locator('xpath=/html/body/div/div/div/div[2]/div[2]/section/div[2]/div[3]/button')
        await elem.click(timeout=10000)
        
        # -> Click the 'Live Incident' link in the left navigation to open the incident view.
        # Live Incident link
        elem = page.get_by_role('link', name='Live Incident', exact=True)
        await elem.click(timeout=10000)
        
        # --> Assertions to verify final state
        
        # --> Verify incident replay content is displayed
        await page.locator("xpath=/html/body/div[1]/div/div/div[2]/div[2]/section/div[1]/button[2]").nth(0).scroll_into_view_if_needed()
        # Assert: The incident replay 'Replay' control is visible.
        await expect(page.locator("xpath=/html/body/div[1]/div/div/div[2]/div[2]/section/div[1]/button[2]").nth(0)).to_be_visible(timeout=15000), "The incident replay 'Replay' control is visible."
        # Assert: A replay event entry (T1550.002) is visible in the correlated attack chain replay.
        await expect(page.locator("xpath=/html/body/div[1]/div/div/div[2]/div[2]/section/div[2]/div[1]/div[2]/span/span").nth(0)).to_contain_text("T1550.002", timeout=15000), "A replay event entry (T1550.002) is visible in the correlated attack chain replay."
        
        # --> Verify an audit-ready incident report is displayed
        await page.locator("xpath=/html/body/div[1]/div/div/div[2]/section[2]/div[1]/button[1]").nth(0).scroll_into_view_if_needed()
        # Assert: The audit-ready incident report displays a 'Download .md' button.
        await expect(page.locator("xpath=/html/body/div[1]/div/div/div[2]/section[2]/div[1]/button[1]").nth(0)).to_be_visible(timeout=15000), "The audit-ready incident report displays a 'Download .md' button."
        await page.locator("xpath=/html/body/div[1]/div/div/div[2]/section[2]/div[1]/button[2]").nth(0).scroll_into_view_if_needed()
        # Assert: The audit-ready incident report displays a 'Print' button.
        await expect(page.locator("xpath=/html/body/div[1]/div/div/div[2]/section[2]/div[1]/button[2]").nth(0)).to_be_visible(timeout=15000), "The audit-ready incident report displays a 'Print' button."
        await asyncio.sleep(5)

    finally:
        if context:
            await context.close()
        if browser:
            await browser.close()
        if pw:
            await pw.stop()

asyncio.run(run_test())
    
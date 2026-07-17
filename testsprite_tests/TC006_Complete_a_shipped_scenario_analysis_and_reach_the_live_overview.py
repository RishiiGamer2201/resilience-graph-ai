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
        
        # -> Click the 'Analyze' button for 'LANL red-team campaign — all 104 accounts' to start the analysis pipeline.
        # Analyze button
        elem = page.locator('xpath=/html/body/div/div/div/div[2]/div[2]/section/div[2]/div[3]/button')
        await elem.click(timeout=10000)
        
        # --> Assertions to verify final state
        
        # --> Verify the live analysis overview is displayed
        # Assert: The URL contains 'overview', confirming the Overview page is loaded.
        await expect(page).to_have_url(re.compile("overview"), timeout=15000), "The URL contains 'overview', confirming the Overview page is loaded."
        # Assert: The sidebar 'Overview' link points to /overview, verifying the Overview section is active.
        await expect(page.locator("xpath=/html/body/div/div/aside/nav[1]/a[2]").nth(0)).to_have_attribute("href", "/overview", timeout=15000), "The sidebar 'Overview' link points to /overview, verifying the Overview section is active."
        # Assert: An Overview page element with text 'MTTD' is visible, confirming the live analysis overview content is present.
        await expect(page.locator("xpath=/html/body/div/div/div/div[2]/section[1]/div[1]/span[2]").nth(0)).to_have_text("MTTD", timeout=15000), "An Overview page element with text 'MTTD' is visible, confirming the live analysis overview content is present."
        
        # --> Verify a live incident context is visible
        await page.locator("xpath=/html/body/div/div/aside/nav[1]/a[4]").nth(0).scroll_into_view_if_needed()
        # Assert: The Live Incident navigation item is visible.
        await expect(page.locator("xpath=/html/body/div/div/aside/nav[1]/a[4]").nth(0)).to_be_visible(timeout=15000), "The Live Incident navigation item is visible."
        # Assert: The Live Incident alert indicator is marked with aria-label 'active alert'.
        await expect(page.locator("xpath=/html/body/div/div/aside/nav[1]/a[4]/span[2]").nth(0)).to_have_attribute("aria-label", "active alert", timeout=15000), "The Live Incident alert indicator is marked with aria-label 'active alert'."
        await asyncio.sleep(5)

    finally:
        if context:
            await context.close()
        if browser:
            await browser.close()
        if pw:
            await pw.stop()

asyncio.run(run_test())
    
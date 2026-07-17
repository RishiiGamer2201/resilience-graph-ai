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
        
        # -> Navigate to the Attackers page (open /attackers) and load its roster view.
        await page.goto("http://localhost:5173/attackers")
        try:
            await page.wait_for_load_state("domcontentloaded", timeout=5000)
        except Exception:
            pass
        
        # -> Click the 'Open incident' button for account U66@DOM1 in the roster.
        # Open incident button
        elem = page.get_by_text('U66@DOM1', exact=True).locator("xpath=ancestor-or-self::*[.//button][1]").get_by_role('button', name='Open incident', exact=True)
        await elem.click(timeout=10000)
        
        # --> Assertions to verify final state
        
        # --> Verify the scoped incident view is displayed
        # Assert: The current URL contains 'incident', indicating the incident view is open.
        await expect(page).to_have_url(re.compile("incident"), timeout=15000), "The current URL contains 'incident', indicating the incident view is open."
        await page.locator("xpath=/html/body/div[1]/div/aside/nav[1]/a[4]").nth(0).scroll_into_view_if_needed()
        # Assert: The 'Live Incident' navigation item is visible, confirming the incident view is displayed.
        await expect(page.locator("xpath=/html/body/div[1]/div/aside/nav[1]/a[4]").nth(0)).to_be_visible(timeout=15000), "The 'Live Incident' navigation item is visible, confirming the incident view is displayed."
        # Assert: The Live Incident nav shows an active alert aria-label, indicating the scoped incident is selected.
        await expect(page.locator("xpath=/html/body/div[1]/div/aside/nav[1]/a[4]/span[2]").nth(0)).to_have_attribute("aria-label", "active alert", timeout=15000), "The Live Incident nav shows an active alert aria-label, indicating the scoped incident is selected."
        
        # --> Verify the selected account is represented in the incident context
        # Assert: Selected account U66 is displayed in the incident context.
        await expect(page.locator("xpath=/html/body/div[1]").nth(0)).to_contain_text("Account U66 in the DOM1 domain", timeout=15000), "Selected account U66 is displayed in the incident context."
        await asyncio.sleep(5)

    finally:
        if context:
            await context.close()
        if browser:
            await browser.close()
        if pw:
            await pw.stop()

asyncio.run(run_test())
    
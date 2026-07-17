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
        
        # -> Open the Threat Intelligence page (Threat Intel) and check for technique-chip UI.
        await page.goto("http://localhost:5173/threat-intel")
        try:
            await page.wait_for_load_state("domcontentloaded", timeout=5000)
        except Exception:
            pass
        
        # -> Add technique chips by clicking the 'T1550.002' and 'T1110' quick add buttons, then click the 'Predict next technique' button.
        # + T1550.002 button
        elem = page.get_by_role('button', name='+ T1550.002', exact=True)
        await elem.click(timeout=10000)
        
        # -> Add technique chips by clicking the 'T1550.002' and 'T1110' quick add buttons, then click the 'Predict next technique' button.
        # + T1110 button
        elem = page.get_by_role('button', name='+ T1078', exact=True)
        await elem.click(timeout=10000)
        
        # -> Add technique chips by clicking the 'T1550.002' and 'T1110' quick add buttons, then click the 'Predict next technique' button.
        # Predict next technique button
        elem = page.get_by_role('button', name='Predict next technique', exact=True)
        await elem.click(timeout=10000)
        
        # --> Assertions to verify final state
        
        # --> Verify ranked next-technique predictions are displayed
        await page.locator("xpath=/html/body/div[1]/div/div/div[2]/div/div/section[2]/div[2]/div[4]/div[2]/div[1]/span[1]").nth(0).scroll_into_view_if_needed()
        # Assert: The ranked predictions panel shows a top entry with rank '1'.
        await expect(page.locator("xpath=/html/body/div[1]/div/div/div[2]/div/div/section[2]/div[2]/div[4]/div[2]/div[1]/span[1]").nth(0)).to_be_visible(timeout=15000), "The ranked predictions panel shows a top entry with rank '1'."
        await page.locator("xpath=/html/body/div[1]/div/div/div[2]/div/div/section[2]/div[2]/div[4]/div[2]/div[1]/span[2]").nth(0).scroll_into_view_if_needed()
        # Assert: The top predicted technique 'T1018' is visible in the predictions list.
        await expect(page.locator("xpath=/html/body/div[1]/div/div/div[2]/div/div/section[2]/div[2]/div[4]/div[2]/div[1]/span[2]").nth(0)).to_be_visible(timeout=15000), "The top predicted technique 'T1018' is visible in the predictions list."
        await page.locator("xpath=/html/body/div[1]/div/div/div[2]/div/div/section[2]/div[2]/div[4]/div[2]/div[3]/span[2]").nth(0).scroll_into_view_if_needed()
        # Assert: A lower-ranked predicted technique ('T1083') is visible, confirming multiple ranked predictions are shown.
        await expect(page.locator("xpath=/html/body/div[1]/div/div/div[2]/div/div/section[2]/div[2]/div[4]/div[2]/div[3]/span[2]").nth(0)).to_be_visible(timeout=15000), "A lower-ranked predicted technique ('T1083') is visible, confirming multiple ranked predictions are shown."
        
        # --> Verify the partial ATT&CK chain is reflected
        await page.locator("xpath=/html/body/div[1]/div/div/div[2]/div/div/section[2]/div[2]/div[2]/span[1]/button").nth(0).scroll_into_view_if_needed()
        # Assert: The Observed ATT&CK chain includes a T1566.001 chip (remove button is visible).
        await expect(page.locator("xpath=/html/body/div[1]/div/div/div[2]/div/div/section[2]/div[2]/div[2]/span[1]/button").nth(0)).to_be_visible(timeout=15000), "The Observed ATT&CK chain includes a T1566.001 chip (remove button is visible)."
        await page.locator("xpath=/html/body/div[1]/div/div/div[2]/div/div/section[2]/div[2]/div[2]/span[2]/button").nth(0).scroll_into_view_if_needed()
        # Assert: The Observed ATT&CK chain includes a T1204.002 chip (remove button is visible).
        await expect(page.locator("xpath=/html/body/div[1]/div/div/div[2]/div/div/section[2]/div[2]/div[2]/span[2]/button").nth(0)).to_be_visible(timeout=15000), "The Observed ATT&CK chain includes a T1204.002 chip (remove button is visible)."
        await page.locator("xpath=/html/body/div[1]/div/div/div[2]/div/div/section[2]/div[2]/div[2]/span[3]/button").nth(0).scroll_into_view_if_needed()
        # Assert: The Observed ATT&CK chain includes a T1550.002 chip (remove button is visible).
        await expect(page.locator("xpath=/html/body/div[1]/div/div/div[2]/div/div/section[2]/div[2]/div[2]/span[3]/button").nth(0)).to_be_visible(timeout=15000), "The Observed ATT&CK chain includes a T1550.002 chip (remove button is visible)."
        await page.locator("xpath=/html/body/div[1]/div/div/div[2]/div/div/section[2]/div[2]/div[2]/span[4]/button").nth(0).scroll_into_view_if_needed()
        # Assert: The Observed ATT&CK chain includes a T1110 chip (remove button is visible).
        await expect(page.locator("xpath=/html/body/div[1]/div/div/div[2]/div/div/section[2]/div[2]/div[2]/span[4]/button").nth(0)).to_be_visible(timeout=15000), "The Observed ATT&CK chain includes a T1110 chip (remove button is visible)."
        await asyncio.sleep(5)

    finally:
        if context:
            await context.close()
        if browser:
            await browser.close()
        if pw:
            await pw.stop()

asyncio.run(run_test())
    
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
        
        # -> Click the 'Enter demo environment' button to open the demo application (expected to go to the Analyze page).
        # Enter demo environment button
        elem = page.get_by_role('button', name='Enter demo environment', exact=True)
        await elem.click(timeout=10000)
        
        # -> Click the 'Analyze' button on the LANL red-team campaign — all 104 accounts card to run the analysis.
        # Analyze button
        elem = page.locator('xpath=/html/body/div/div/div/div[2]/div[2]/section/div[2]/div[3]/button')
        await elem.click(timeout=10000)
        
        # -> Click the 'Threat Intel & Attribution' link in the left navigation to open the Threat Intel view.
        # Threat Intel & Attribution link
        elem = page.get_by_role('link', name='Threat Intel & Attribution', exact=True)
        await elem.click(timeout=10000)
        
        # -> Fill 'T1059.001' into the 'Add technique id' field and click the 'Add technique' button, then click the 'Predict next technique' button.
        # Add technique id text field
        elem = page.get_by_label('Add technique id', exact=True)
        await elem.wait_for(state="visible", timeout=10000)
        await elem.fill("T1059.001")
        
        # -> Fill 'T1059.001' into the 'Add technique id' field and click the 'Add technique' button, then click the 'Predict next technique' button.
        # Add technique button
        elem = page.get_by_role('button', name='Add technique', exact=True)
        await elem.click(timeout=10000)
        
        # -> Fill 'T1059.001' into the 'Add technique id' field and click the 'Add technique' button, then click the 'Predict next technique' button.
        # Predict next technique button
        elem = page.get_by_role('button', name='Predict next technique', exact=True)
        await elem.click(timeout=10000)
        
        # --> Assertions to verify final state
        
        # --> Verify a next-technique prediction is displayed
        # Assert: A predicted next technique entry labeled 'Python' is displayed.
        await expect(page.locator("xpath=/html/body/div[1]/div/div/div[2]/div/div/section[2]/div[2]/div[4]/div[2]/div[4]/span[3]").nth(0)).to_contain_text("Python", timeout=15000), "A predicted next technique entry labeled 'Python' is displayed."
        
        # --> Verify the ATT&CK context remains visible
        await page.locator("xpath=/html/body/div[1]/div/div/div[2]/div/div/section[2]/div[2]/div[2]/span[1]/button").nth(0).scroll_into_view_if_needed()
        # Assert: The ATT&CK context shows a Remove button for T1566.001, confirming the context is visible.
        await expect(page.locator("xpath=/html/body/div[1]/div/div/div[2]/div/div/section[2]/div[2]/div[2]/span[1]/button").nth(0)).to_be_visible(timeout=15000), "The ATT&CK context shows a Remove button for T1566.001, confirming the context is visible."
        await page.locator("xpath=/html/body/div[1]/div/div/div[2]/div/div/section[2]/div[2]/div[2]/span[2]/button").nth(0).scroll_into_view_if_needed()
        # Assert: The ATT&CK context shows a Remove button for T1204.002, confirming the context is visible.
        await expect(page.locator("xpath=/html/body/div[1]/div/div/div[2]/div/div/section[2]/div[2]/div[2]/span[2]/button").nth(0)).to_be_visible(timeout=15000), "The ATT&CK context shows a Remove button for T1204.002, confirming the context is visible."
        await page.locator("xpath=/html/body/div[1]/div/div/div[2]/div/div/section[2]/div[2]/div[2]/span[3]/button").nth(0).scroll_into_view_if_needed()
        # Assert: The ATT&CK context shows a Remove button for T1059.001, confirming the context is visible.
        await expect(page.locator("xpath=/html/body/div[1]/div/div/div[2]/div/div/section[2]/div[2]/div[2]/span[3]/button").nth(0)).to_be_visible(timeout=15000), "The ATT&CK context shows a Remove button for T1059.001, confirming the context is visible."
        await page.locator("xpath=/html/body/div[1]/div/div/div[2]/div/div/section[2]/div[2]/div[2]/form/input").nth(0).scroll_into_view_if_needed()
        # Assert: The Add technique id input is still visible, confirming the ATT&CK context UI remains present.
        await expect(page.locator("xpath=/html/body/div[1]/div/div/div[2]/div/div/section[2]/div[2]/div[2]/form/input").nth(0)).to_be_visible(timeout=15000), "The Add technique id input is still visible, confirming the ATT&CK context UI remains present."
        await asyncio.sleep(5)

    finally:
        if context:
            await context.close()
        if browser:
            await browser.close()
        if pw:
            await pw.stop()

asyncio.run(run_test())
    
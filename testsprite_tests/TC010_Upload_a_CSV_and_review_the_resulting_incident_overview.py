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
        
        # -> Click the 'Enter demo environment' button to open the Analyze page.
        # Enter demo environment button
        elem = page.get_by_role('button', name='Enter demo environment', exact=True)
        await elem.click(timeout=10000)
        
        # -> Use the 'Choose CSV' file input to upload a valid CSV and then click the 'Analyze upload' button to start the analysis pipeline.
        # file upload
        elem = page.get_by_label('Choose CSV', exact=True)
        await elem.wait_for(state="attached", timeout=10000)
        if await elem.evaluate("e => e.tagName === 'INPUT' && (e.type || '').toLowerCase() === 'file'"):
            await elem.set_input_files("./fixtures/sample_log.csv")
        else:
            await elem.wait_for(state="visible", timeout=10000)
            async with page.expect_file_chooser() as fc_info:
                await elem.click()
            chooser = await fc_info.value
            await chooser.set_files("./fixtures/sample_log.csv")
        
        # -> Use the 'Choose CSV' file input to upload a valid CSV and then click the 'Analyze upload' button to start the analysis pipeline.
        # Analyze upload button
        elem = page.get_by_role('button', name='Analyze upload', exact=True)
        await elem.click(timeout=10000)
        
        # -> Upload a corrected CSV file using the 'Choose CSV' control and click the 'Analyze upload' button to start analysis.
        # file upload
        elem = page.get_by_label('sample_log.csv', exact=True)
        await elem.wait_for(state="attached", timeout=10000)
        if await elem.evaluate("e => e.tagName === 'INPUT' && (e.type || '').toLowerCase() === 'file'"):
            await elem.set_input_files("./fixtures/sample_log_fixed.csv")
        else:
            await elem.wait_for(state="visible", timeout=10000)
            async with page.expect_file_chooser() as fc_info:
                await elem.click()
            chooser = await fc_info.value
            await chooser.set_files("./fixtures/sample_log_fixed.csv")
        
        # -> Upload a corrected CSV file using the 'Choose CSV' control and click the 'Analyze upload' button to start analysis.
        # Analyze upload button
        elem = page.get_by_role('button', name='Analyze upload', exact=True)
        await elem.click(timeout=10000)
        
        # --> Assertions to verify final state
        
        # --> Verify the live analysis overview is displayed
        # Assert: The browser is on the /overview page showing the live analysis overview.
        await expect(page).to_have_url(re.compile("/overview"), timeout=15000), "The browser is on the /overview page showing the live analysis overview."
        await page.locator("xpath=/html/body/div[1]/div/div/div[2]/section[1]/div[1]/span[2]").nth(0).scroll_into_view_if_needed()
        # Assert: The overview page displays the 'MTTD' label, indicating live analysis content is shown.
        await expect(page.locator("xpath=/html/body/div[1]/div/div/div[2]/section[1]/div[1]/span[2]").nth(0)).to_be_visible(timeout=15000), "The overview page displays the 'MTTD' label, indicating live analysis content is shown."
        
        # --> Verify incident summary content is visible
        # Assert: The incident summary 'MTTD' label is visible.
        await expect(page.locator("xpath=/html/body/div[1]/div/div/div[2]/section[1]/div[1]/span[2]").nth(0)).to_have_text("MTTD", timeout=15000), "The incident summary 'MTTD' label is visible."
        # Assert: The incident summary includes the model descriptor 'real'.
        await expect(page.locator("xpath=/html/body/div[1]/div/div/div[2]/section[2]/div[2]/div/div[2]/span").nth(0)).to_have_text("real", timeout=15000), "The incident summary includes the model descriptor 'real'."
        # Assert: The incident summary includes the model descriptor 'honest'.
        await expect(page.locator("xpath=/html/body/div[1]/div/div/div[2]/section[2]/div[2]/div/div[4]/span").nth(0)).to_have_text("honest", timeout=15000), "The incident summary includes the model descriptor 'honest'."
        await asyncio.sleep(5)

    finally:
        if context:
            await context.close()
        if browser:
            await browser.close()
        if pw:
            await pw.stop()

asyncio.run(run_test())
    
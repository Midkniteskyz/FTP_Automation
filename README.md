## PowerShell Script: FTP Automation and Management

### Overview

This PowerShell script facilitates automated FTP file transfers and manages FTP-related tasks. It includes functions for sending files to an FTP server, configuring Windows Firewall exceptions for FTP, adding necessary FTP features to Windows, creating an FTP site, and providing an interactive menu for easy navigation. The script is designed to simplify FTP operations, making it particularly useful for scenarios involving regular file transfers.

### How to Use

1. **Running the Script:**

    Save the script in a file named `FTP_Automation.ps1` and execute it using PowerShell. Open PowerShell, navigate to the directory containing the script, and run the following command:

    ```powershell
    .\FTP_Automation.ps1
    ```

2. **Main Menu:**

    Upon execution, the script presents a main menu that offers two main categories: FTP Client and FTP Server.

    - **FTP Client:** This section deals with client-side FTP tasks.

        - **Automatic Set-Up (Option 1):** Automates the set-up of FTP-related components, including directory creation, firewall configuration, and task scheduling for regular transfers.

        - **Custom Tasks (Option 2):** Provides several options for performing specific FTP-related tasks manually.

    - **FTP Server:** This section focuses on server-side FTP tasks.

        - **Automatic Set-Up (Option 1):** Adds necessary FTP features to Windows, creates an FTP site, and initiates a server reboot.

        - **Add Windows FTP Features (Option 2):** Adds the required FTP-related Windows features.

        - **Create FTP Site (Option 3):** Creates a new FTP site on the server.

3. **FTP Client:**

    - **Automatic Set-Up (Option 1):**

        This option automatically performs the following steps:

        - Creates necessary directory paths for the FTP process.
        - Copies the script to the FTP script directory.
        - Configures the Windows Firewall to allow FTP traffic.
        - Imports a scheduled task that initiates FTP transfers.

        After selecting this option, the script will guide you through each step.

    - **Custom Tasks (Option 2):**

        This option provides various FTP-related tasks that can be performed manually. These include:

        - Configuring the client firewall for FTP.
        - Manually uploading a single file to an FTP server.
        - Manually uploading all files in a directory to an FTP server.
        - Importing the scheduled task for FTP transfers.

        Selecting any of these options will guide you through the necessary steps.

4. **FTP Server:**

    - **Automatic Set-Up (Option 1):**

        This option automatically performs the following steps:

        - Adds required FTP features to Windows Server.
        - Creates an FTP site.
        - Initiates a server reboot.

    - **Add Windows FTP Features (Option 2):**

        This option adds the necessary FTP features to Windows. This step is required before creating an FTP site.

    - **Create FTP Site (Option 3):**

        This option guides you through the process of creating an FTP site on the server. You'll need to provide details such as the site name, physical path, and port.

5. **File Transfer Trigger:**

    If you run the script with the `-TriggerFTP` parameter (e.g., `.\FTP_Automation.ps1 -TriggerFTP`), the script will trigger automated file transfers without presenting the menu. It scans the `C:\FTP\Outbound` directory and sends its contents to the specified FTP server.

### Important Notes

- This script is designed to run on Windows-based systems and requires PowerShell.
- Use caution when automating sensitive tasks, such as configuring the firewall and initiating server reboots.
- Before using the script in a production environment, thoroughly test it in a controlled setting.
- ***After configuring the client side, you must go into Task Scheduler and manually start the new task.***

Remember that this script may require adjustments based on your specific network configuration, security policies, and FTP server settings.

### Conclusion

This script offers a convenient solution for automating FTP file transfers and managing FTP-related tasks in a Windows environment. By following the provided instructions, you can perform various FTP operations efficiently, making it an invaluable tool for scenarios that involve routine FTP transfers. Always exercise caution and review the script to ensure its compatibility with your environment before implementation.

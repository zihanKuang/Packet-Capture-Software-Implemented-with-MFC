# Sniffer

A **WinPcap-based network packet sniffer** implemented in MFC (Visual C++). This project demonstrates how to:

1. **Select a network adapter** (via `CAdpDlg`).
2. **Set capture filters** (via `CFilterDlg`).
3. **Capture and parse packets** (TCP, UDP, ICMP, ARP, DNS, etc.).
4. **Display** both a **list view** (summary) and **tree view** (detailed protocol layers).
5. **Save** the hex dump of captured data to a local file (`Record.txt`).

## Features

1. **Adapter Selection**
   - The `CAdpDlg` dialog enumerates local network interfaces using WinPcap (i.e., `pcap_findalldevs_ex`) and allows you to select one adapter for subsequent packet capture.
2. **Protocol Filter**
   - The `CFilterDlg` dialog provides checkboxes for TCP, UDP, ARP, ICMP, and DNS. Once filters are chosen, the combined expression is compiled via `pcap_compile` and applied with `pcap_setfilter`.
3. **Packet Capture**
   - Uses a **capture thread** (`CreateThread`) that runs `CapturePacket` continuously until the user clicks *Stop* or closes the program.
   - Captures raw Ethernet frames, parses the headers (Ethernet, ARP/IP, TCP/UDP/ICMP, DNS), and displays relevant fields in a list control.
4. **Live Display**
   - **List View** (`CListCtrl`): Summarizes each packet with time, MACs, IPs, protocol, and length.
   - **Tree View** (`CTreeCtrl`): Shows a hierarchical breakdown of each protocol header (Ethernet layer → Network layer → Transport layer → Application layer).
5. **Hex Dump**
   - For each selected packet, a formatted hex dump is appended to **Record.txt**.
   - Additionally, the raw bytes for the selected packet appear in the text edit control (`IDC_EDIT1`).
6. **MFC**
   - Standard MFC dialogs, controls, resource files, and a main application class `CSnifferApp`.

## Building & Requirements

1. **Prerequisites**
   - **Visual Studio** (the project is in `.vcxproj` and `.sln` format).
   - **WinPcap** or **Npcap** SDK installed (headers + libraries in `IncludePath` and `LibraryPath`). The `.vcxproj` references `WpdPack_4_1_2\WpdPack` paths—adjust these to your local WinPcap/Npcap path.
2. **Clone & Open**
   - Clone or download the repository.
   - Open `Sniffer.sln` in Visual Studio.
3. **Configuration**
   - The solution supports **Debug** and **Release** configurations for **Win32** and **x64**.
   - Ensure your `IncludePath` and `LibraryPath` point to the correct WinPcap/Npcap installation. Check the `.vcxproj` to update if needed.
4. **Build**
   - Right-click the project → **Build**.
   - If the compilation is successful, you get an **EXE** (e.g., `Debug\Sniffer.exe`).

## How to Use

1. **Start the Application**
   - Run the generated `Sniffer.exe`.
2. **Select Adapter**
   - Go to **Menu** → **Adp**.
   - In the **CAdpDlg** dialog, choose the network interface you want to capture from. Click **OK** to bind.
3. **Set Filter** *(optional)*
   - Go to **Menu** → **Filter**.
   - Check or uncheck protocols (TCP, UDP, ARP, ICMP, DNS) and click **OK**.
   - This sets up a BPF (Berkeley Packet Filter) expression behind the scenes.
4. **Start Capture**
   - Go to **Menu** → **Start**.
   - A worker thread begins capturing packets. Newly captured packets appear in the **list view** with summarized info.
5. **Stop Capture**
   - Go to **Menu** → **Stop**.
   - The capture thread stops.
6. **Inspect Packet Details**
   - Click a packet in the list to view a hierarchical breakdown in the **tree view** (Ethernet → IP → TCP/UDP/ICMP, etc.).
   - The **edit box** shows the raw bytes (hex dump).
   - The project also appends this hex dump to the text file **Record.txt** for your reference.

## Project Structure

- **Sniffer.sln / Sniffer.vcxproj**
  The main solution and project files for Visual Studio.
- **Sniffer.cpp / SnifferDlg.cpp**
  MFC application entry point and the main dialog that handles capturing logic.
- **CAdpDlg.cpp**
  Dialog for listing/choosing local network adapters.
- **CFilterDlg.cpp**
  Dialog for filtering packets by protocols (TCP/UDP/ICMP/ARP/DNS).
- **head.h**
  Contains protocol header structures (Ethernet, IP, TCP, UDP, ARP, ICMP, DNS).
- **Record.txt**
  The output file where hex dumps are appended each time you click on a captured packet.

## Notes & Tips

- If you have **Npcap** instead of **WinPcap**, check that `pcap_findalldevs_ex` and related calls are still valid. In many cases, Npcap is backward compatible, but be mindful of the installation path.
- By default, the project is set to **promiscuous mode** to capture all traffic passing the chosen adapter.
- The hex dump logic in `ShowPacketList()` appends data to `Record.txt` at runtime. This is a simplistic approach; watch out for concurrency issues if you adapt it for multi-threaded usage.
- The filter expression is compiled with `pcap_compile(...)`; an empty or invalid filter results in capturing **all** packets. Ensure your `BPF` expression is valid if you rely on advanced filters.


// SnifferDlg.cpp: 实现文件
//

#include "pch.h"
#include "framework.h"
#include "Sniffer.h"
#include "SnifferDlg.h"
#include "afxdialogex.h"
#include "head.h"
#include <fstream>

#include "CAdpDlg.h"
#include "CFilterDlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif
using namespace std;

DWORD WINAPI CapturePacket(LPVOID lpParam);
// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();
	//CAdpDlg m_adpDlg;
	//CFilterDlg m_filterDlg;

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CSnifferDlg 对话框
CSnifferDlg::CSnifferDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_SNIFFER_DIALOG, pParent)
	, m_tcpnum(_T(""))
	, m_udpnum(_T(""))
	, m_arpnum(_T(""))
	, m_icmpnum(_T(""))
	, m_dnsnum(_T(""))

{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
	m_shouldStop = TRUE;
	m_hThread = INVALID_HANDLE_VALUE;
	m_pDevice = NULL;
}

void CSnifferDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_EDIT1, m_edit1);
	DDX_Text(pDX, IDC_EDIT2, m_tcpnum);
	DDX_Text(pDX, IDC_EDIT3, m_udpnum);
	DDX_Text(pDX, IDC_EDIT4, m_arpnum);
	DDX_Text(pDX, IDC_EDIT5, m_icmpnum);
	DDX_Text(pDX, IDC_EDIT7, m_dnsnum);
	DDX_Control(pDX, IDC_LIST1, m_list1);
	DDX_Control(pDX, IDC_TREE1, m_tree1);
}

BEGIN_MESSAGE_MAP(CSnifferDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_COMMAND(ID_Adp, &CSnifferDlg::OnAdp)
	ON_COMMAND(ID_Filter, &CSnifferDlg::OnFilter)
	ON_COMMAND(ID_Start, &CSnifferDlg::OnStart)
	ON_COMMAND(ID_Stop, &CSnifferDlg::OnStop)
	ON_COMMAND(ID_Save, &CSnifferDlg::OnSave)
	ON_NOTIFY(LVN_ITEMCHANGED, IDC_LIST1, &CSnifferDlg::OnLvnItemchangedList1)
END_MESSAGE_MAP()


// CSnifferDlg 消息处理程序

BOOL CSnifferDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();
	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	m_pDevice = NULL;
	m_shouldStop = true;

	// TODO: 在此添加额外的初始化代码
	m_list1.SetExtendedStyle(m_list1.GetExtendedStyle() | LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);// 为列表视图控件添加全行选中和栅格风格
	m_list1.InsertColumn(0, _T("序号"), LVCFMT_CENTER, 50);
	m_list1.InsertColumn(1, _T("时间"), LVCFMT_CENTER, 120);
	m_list1.InsertColumn(2, _T("源MAC地址"), LVCFMT_CENTER, 120);
	m_list1.InsertColumn(3, _T("目的MAC地址"), LVCFMT_CENTER, 120);
	m_list1.InsertColumn(4, _T("长度"), LVCFMT_CENTER, 50);
	m_list1.InsertColumn(5, _T("协议"), LVCFMT_CENTER, 70);
	m_list1.InsertColumn(6, _T("源IP地址"), LVCFMT_CENTER, 120);
	m_list1.InsertColumn(7, _T("目的IP地址"), LVCFMT_CENTER, 120);

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CSnifferDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CSnifferDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CSnifferDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


void CSnifferDlg::OnAdp()
{
	// TODO: 在此添加命令处理程序代码
	CAdpDlg adpdlg;
	if (adpdlg.DoModal() == IDOK)
	{
		m_pDevice = adpdlg.returnd();
	}
}

void CSnifferDlg::OnFilter()
{
	// TODO: 在此添加命令处理程序代码
	CFilterDlg filterdlg;
	if (filterdlg.DoModal() == IDOK)
	{
		int len = WideCharToMultiByte(CP_ACP, 0, filterdlg.GetFilterName(), -1, NULL, 0, NULL, NULL);
		WideCharToMultiByte(CP_ACP, 0, filterdlg.GetFilterName(), -1, m_filtername, len, NULL, NULL);
	}
}

DWORD WINAPI CapturePacket(LPVOID lpParam)
{
	CSnifferDlg* pDlg = (CSnifferDlg*)lpParam;
	pcap_t* pCap;
	char    strErrorBuf[PCAP_ERRBUF_SIZE];
	int res;
	struct pcap_pkthdr* pkt_header;
	const u_char* pkt_data;
	u_int netmask;
	struct bpf_program fcode;

	memset(strErrorBuf, 0, PCAP_ERRBUF_SIZE);

	//pcap_open_live()用于获取数据包捕获描述符以查看网络上的数据包
	//
	if ((pCap = pcap_open_live(pDlg->m_pDevice->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, strErrorBuf)) == NULL)
	{
		return -1;
	}

	if (pDlg->m_pDevice->addresses != NULL)
		/* 获得接口第一个地址的掩码 */
		netmask = ((struct sockaddr_in*)(pDlg->m_pDevice->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* 如果接口没有地址，那么我们假设一个C类的掩码 */
		netmask = 0xffffff;
	//编译过滤器
	//if (pcap_compile(pCap, &fcode, pDlg->m_filtername, 1, netmask) < 0)
	if (pcap_compile(pCap, &fcode, pDlg->m_filtername, 0, netmask) < 0)
	{
		CString strMsg;
		//strMsg.Format(_T("编译过滤器失败：%s"), pcap_geterr(pCap));
		AfxMessageBox(_T("请设置过滤规则"));
		pcap_close(pCap);
		return -1;
	}
	//设置过滤器
	if (pcap_setfilter(pCap, &fcode) < 0)
	{
		CString strMsg;
		//strMsg.Format(_T("设置过滤器失败：%s"), pcap_geterr(pCap));
		AfxMessageBox(strMsg);
		pcap_close(pCap);
		return -1;
	}

	while ((res = pcap_next_ex(pCap, &pkt_header, &pkt_data)) >= 0)
	{

		if (res == 0)
			continue;
		if (pDlg->m_shouldStop)
			break;

		CSnifferDlg* pDlg = (CSnifferDlg*)AfxGetApp()->GetMainWnd();

		pDlg->ShowPacketList(pkt_header, pkt_data);
		pDlg = NULL;
	}

	pcap_close(pCap);
	pDlg = NULL;
	return 1;
}

void CSnifferDlg::OnSave()
{
	// TODO: 在此添加命令处理程序代码
	//if (this->savefile() < 0)
		return;
}

void CSnifferDlg::OnStop()
{
	// 重置标记
	m_shouldStop = TRUE;
}

void CSnifferDlg::OnStart()
{

	if (m_pDevice == NULL)
	{
		AfxMessageBox(_T("请选择要绑定的网卡"));
		return;
	}

	// 开始抓包
	m_shouldStop = FALSE;

	m_hThread = CreateThread(NULL, NULL, CapturePacket, (LPVOID)this, true, NULL);
	if (m_hThread == NULL)
	{
		MessageBox(_T("线程启动失败"));
		return;
	}else
	{
		OutputDebugString(_T("线程已启动"));
	}

	/*不需要在开始/停止捕获数据时更新UI状态（比如禁用/启用按钮）*/
}

void CSnifferDlg::ShowPacketList(const struct pcap_pkthdr* pkt_header, const u_char* pkt_data)
{
	struct pcap_pkthdr* pHeader = new pcap_pkthdr;
	u_char* pData;

	pHeader->caplen = pkt_header->caplen;
	pHeader->len = pkt_header->len;

	pData = new unsigned char[pHeader->len];
	memcpy((void*)pData, pkt_data, pHeader->len);

	int pkt_length = pkt_header->len;

	long nIndex = 0;//标识当前的数据包位置
	long nCount = 0;//标识后来

		// 将数据包信息添加到列表视图中
	int nItemIndex = m_list1.GetItemCount();
	CString strIndex;
	strIndex.Format(_T("%d"), nItemIndex + 1);
	m_list1.InsertItem(nItemIndex, strIndex);

	//用于存诸网络中的数据，并保存到CArray中,以备将来使用
	m_pktHeaders.Add(pHeader);
	m_pktDatas.Add(pData);

	nIndex = m_pktHeaders.GetSize() - 1;
	CString str;
	str.Format(_T("%d"), nIndex);

	// 获取系统当前时间
	CString strTime;
	CTime t = CTime::GetCurrentTime();
	strTime = t.Format("%H:%M:%S");
	m_list1.SetItemText(nItemIndex, 1, strTime);

	// 解析数据包的以太网头部(链路层-网络层-传输层-应用层）
	//前14个字节为以太网帧头部
	const struct eth_hdr* eh;
	eh = (const struct eth_hdr*)pkt_data;

	// 获取源MAC地址
	//%02X表示将一个无符号整数以16进制形式输出
	CString strSrcMacAddr;
	strSrcMacAddr.Format(_T("%02X:%02X:%02X:%02X:%02X:%02X"),
		eh->src[0], eh->src[1],
		eh->src[2], eh->src[3],
		eh->src[4], eh->src[5]);
	m_list1.SetItemText(nItemIndex, 2, strSrcMacAddr);

	// 获取目的MAC地址
	CString strDstMacAddr;
	strDstMacAddr.Format(_T("%02X:%02X:%02X:%02X:%02X:%02X"),
		eh->dest[0], eh->dest[1],
		eh->dest[2], eh->dest[3],
		eh->dest[4], eh->dest[5]);
	m_list1.SetItemText(nItemIndex, 3, strDstMacAddr);

	str.Format(_T("%ld"), pHeader->len);
	m_list1.SetItemText(nItemIndex, 4, str);

	CString strSrcIp;
	CString strDstIp;

	// 判断数据包的类型，并解析出对应的协议头部信息
	CString strProtocol;
	switch (ntohs(eh->type))
	{

	case MAC_IP:      // IPv4协议
	{
		strProtocol = _T("IPv4");

		// 解析IPv4头部
		const struct ip_hdr* iph;
		const u_char* ip_data;
		ip_data = pkt_data + 14;

		iph = (const struct ip_hdr*)(pkt_data + sizeof(struct eth_hdr));

		u_int ip_len;//IP首部长度
		ip_len = (iph->ip_ihl & 0xf) * 4;   //四个字节一单位

		strSrcIp.Format(_T("%d.%d.%d.%d"), iph->ip_src[0], iph->ip_src[1], iph->ip_src[2], iph->ip_src[3]);
		strDstIp.Format(_T("%d.%d.%d.%d"), iph->ip_dest[0], iph->ip_dest[1], iph->ip_dest[2], iph->ip_dest[3]);
		m_list1.SetItemText(nItemIndex, 6, strSrcIp);
		m_list1.SetItemText(nItemIndex, 7, strDstIp);

		//获取协议类型
		switch (iph->ip_type)
		{
		case TRANS_TCP:		//TCP
		{
			strProtocol += _T(" (TCP)");

			tcp_hdr* th;
			const u_char* tcp_data;
			tcp_data = ip_data + ip_len;
			th = (tcp_hdr*)tcp_data;

			// 更新 TCP 计数值
			m_tcpnum.Format(_T("%d"), ++tcpnum);
			GetDlgItem(IDC_EDIT2)->SetWindowText(m_tcpnum);

			if (ntohs(th->tcp_dport) == DNS || ntohs(th->tcp_dport) == DNS)
			{
				m_list1.SetItemText(nItemIndex, 5, _T("DNS"));

				// 更新 DNS 计数值
				m_dnsnum.Format(_T("%d"), ++dnsnum);
				GetDlgItem(IDC_EDIT7)->SetWindowText(m_dnsnum);

			}
			else
			{
				m_list1.SetItemText(nItemIndex, 5, _T("TCP"));
			}
				

			break;
		}
		case TRANS_ICMP:    // ICMP协议
		{
			strProtocol += _T(" (ICMP)");
			m_list1.SetItemText(nItemIndex, 5, _T("ICMP"));

			// 更新 ICMP 计数值
			m_icmpnum.Format(_T("%d"), ++icmpnum);
			GetDlgItem(IDC_EDIT5)->SetWindowText(m_icmpnum);

			break;
		}
		case TRANS_UDP:    // UDP协议
		{
			strProtocol += _T(" (UDP)");

			// 解析UDP头部
			const struct udp_hdr* uh;
			const u_char* udp_data;
			udp_data = ip_data + ip_len;
			uh = (udp_hdr*)udp_data;
			u_short srcPort = ntohs(uh->udp_sport);
			u_short dstPort = ntohs(uh->udp_dport);

			// 更新 UDP 计数值
			m_udpnum.Format(_T("%d"), ++udpnum);
			GetDlgItem(IDC_EDIT3)->SetWindowText(m_udpnum);

			if (srcPort == DNS || dstPort == DNS)
			{
				m_list1.SetItemText(nItemIndex, 5, _T("DNS"));

				// 更新 DNS 计数值
				m_udpnum.Format(_T("%d"), ++udpnum);
				GetDlgItem(IDC_EDIT3)->SetWindowText(m_udpnum);
			}
			else
			{
				m_list1.SetItemText(nItemIndex, 5, _T("UDP"));
			}
			break;
		}
		}
		break;
	}
	case MAC_ARP:     // ARP协议
	{
		strProtocol = _T("ARP");
		m_list1.SetItemText(nItemIndex, 5, _T("ARP"));

		arp_hdr* ah;
		const u_char* arp_data;
		arp_data = pkt_data + 14;
		ah = (arp_hdr*)arp_data;
		str.Format(_T("%d.%d.%d.%d"), ah->ar_srcip[0], ah->ar_srcip[1], ah->ar_srcip[2], ah->ar_srcip[3]);
		m_list1.SetItemText(nItemIndex, 6, str);
		str.Format(_T("%d.%d.%d.%d"), ah->ar_destip[0], ah->ar_destip[1], ah->ar_destip[2], ah->ar_destip[3]);
		m_list1.SetItemText(nItemIndex, 7, str);

		// 更新 ARP 计数值
		m_arpnum.Format(_T("%d"), ++arpnum);
		GetDlgItem(IDC_EDIT4)->SetWindowText(m_arpnum);

		break;
	}
	default:                // 未知协议
	{
		strProtocol = _T("Unknown");
		m_list1.SetItemText(nCount, 5, _T("未知协议"));
		break;
	}
	}
}

void CSnifferDlg::ShowPacketTree(const pcap_pkthdr* pkt_header, const u_char* pkt_data, long index)
{
	m_tree1.DeleteAllItems();   //清除之前的显示
	CString str;
	str.Format(_T("数据包:%ld"), index);
	HTREEITEM hRoot;
	HTREEITEM hSubItem;
	HTREEITEM hItem;
	HTREEITEM hItem2;

	hRoot = m_tree1.InsertItem(str);
	hSubItem = m_tree1.InsertItem(_T("数据链路层"), hRoot);

	eth_hdr* eh;
	eh = (eth_hdr*)pkt_data;
	CString strSrcMacAddr;
	strSrcMacAddr.Format(_T("%02X:%02X:%02X:%02X:%02X:%02X"),
		eh->src[0], eh->src[1],
		eh->src[2], eh->src[3],
		eh->src[4], eh->src[5]);
	hItem = m_tree1.InsertItem(strSrcMacAddr, hSubItem);

	// 获取目的MAC地址
	CString strDstMacAddr;
	strDstMacAddr.Format(_T("%02X:%02X:%02X:%02X:%02X:%02X"),
		eh->dest[0], eh->dest[1],
		eh->dest[2], eh->dest[3],
		eh->dest[4], eh->dest[5]);
	hItem = m_tree1.InsertItem(strDstMacAddr, hSubItem);

	switch (ntohs(eh->type))
	{
	case IP:
	{
		hItem = m_tree1.InsertItem(_T("上层协议:IP"), hSubItem);
		hSubItem = m_tree1.InsertItem(_T("网络层"), hRoot);
		ip_hdr* iph;
		const u_char* ip_data;
		ip_data = pkt_data + 14;
		iph = (ip_hdr*)ip_data;
		u_int ip_len = (iph->ip_ihl & 0xf) * 4;
		str.Format(_T("版本：%d"), iph->ip_version);
		hItem = m_tree1.InsertItem(str, hSubItem);
		str.Format(_T("首部长度：%d"), iph->ip_ihl);
		hItem = m_tree1.InsertItem(str, hSubItem);
		str.Format(_T("服务类型：0x%x"), iph->ip_tos);
		hItem = m_tree1.InsertItem(str, hSubItem);
		str.Format(_T("总长度：%d"), ntohs(iph->ip_tlen));
		hItem = m_tree1.InsertItem(str, hSubItem);
		str.Format(_T("标识：0x%x"), ntohs(iph->ip_id));
		hItem = m_tree1.InsertItem(str, hSubItem);
		str.Format(_T("标志：0x%x"), ntohs(iph->ip_flags_fo) & 0xe000 / 0x2000);
		hItem = m_tree1.InsertItem(str, hSubItem);
		str.Format(_T("片偏移：%d"), ntohs(iph->ip_flags_fo) & 0x1fff);
		hItem = m_tree1.InsertItem(str, hSubItem);
		str.Format(_T("生存时间：%d"), iph->ip_ttl);
		hItem = m_tree1.InsertItem(str, hSubItem);
		str.Format(_T("首部校验和：0x%x"), ntohs(iph->ip_crc));
		hItem = m_tree1.InsertItem(str, hSubItem);
		str.Format(_T("源IP地址：%d.%d.%d.%d"), iph->ip_src[0], iph->ip_src[1], iph->ip_src[2], iph->ip_src[3]);
		hItem = m_tree1.InsertItem(str, hSubItem);
		str.Format(_T("目的IP地址：%d.%d.%d.%d"), iph->ip_dest[0], iph->ip_dest[0], iph->ip_dest[0], iph->ip_dest[0]);
		hItem = m_tree1.InsertItem(str, hSubItem);

		switch (iph->ip_type)
		{
		case TRANS_TCP:
		{
			hItem = m_tree1.InsertItem(_T("上层协议:TCP"), hSubItem);
			hSubItem = m_tree1.InsertItem(_T("传输层"), hRoot);
			tcp_hdr* th;
			const u_char* tcp_data;
			tcp_data = ip_data + ip_len;
			th = (tcp_hdr*)tcp_data;
			str.Format(_T("源端口号：%d"), ntohs(th->tcp_sport));
			hItem = m_tree1.InsertItem(str, hSubItem);
			str.Format(_T("目的口号：%d"), ntohs(th->tcp_dport));
			hItem = m_tree1.InsertItem(str, hSubItem);
			str.Format(_T("顺序号：%d"), ntohs(th->tcp_seq));
			hItem = m_tree1.InsertItem(str, hSubItem);
			str.Format(_T("确认号：%d"), ntohs(th->tcp_ack));
			hItem = m_tree1.InsertItem(str, hSubItem);
			str.Format(_T("TCP头长：%d"), (th->doff * 4));
			hItem = m_tree1.InsertItem(str, hSubItem);
			str.Format(_T("控制位：%d"), (th->ece));
			hItem = m_tree1.InsertItem(str, hSubItem);
			str.Format(_T("紧急URG:%d"), (th->urg));
			hItem2 = m_tree1.InsertItem(str, hItem);
			str.Format(_T("确认ACK:%d"), (th->ack));
			hItem2 = m_tree1.InsertItem(str, hItem);
			str.Format(_T("推送PSH:%d"), (th->psh));
			hItem2 = m_tree1.InsertItem(str, hItem);
			str.Format(_T("复位RSTG:%d"), (th->rst));
			hItem2 = m_tree1.InsertItem(str, hItem);
			str.Format(_T("同步SYN:%d"), (th->syn));
			hItem2 = m_tree1.InsertItem(str, hItem);
			str.Format(_T("结束FIN:%d"), (th->fin));
			hItem2 = m_tree1.InsertItem(str, hItem);
			str.Format(_T("窗口：%d"), ntohs(th->th_win));
			hItem = m_tree1.InsertItem(str, hSubItem);
			str.Format(_T("校验和：0x%x"), ntohs(th->th_ckecksum));
			hItem = m_tree1.InsertItem(str, hSubItem);
			str.Format(_T("紧急指针：0x%x"), ntohs(th->th_urp));
			hItem = m_tree1.InsertItem(str, hSubItem);
			break;
		}
		case TRANS_UDP:
		{
			hItem = m_tree1.InsertItem(_T("上层协议:UDP"), hSubItem);
			hSubItem = m_tree1.InsertItem(_T("传输层"), hRoot);
			udp_hdr* uh;
			const u_char* udp_data;
			udp_data = ip_data + ip_len;
			uh = (udp_hdr*)udp_data;
			str.Format(_T("源端口号：%d"), ntohs(uh->udp_sport));
			hItem = m_tree1.InsertItem(str, hSubItem);
			str.Format(_T("目的端口号：%d"), ntohs(uh->udp_dport));
			hItem = m_tree1.InsertItem(str, hSubItem);
			str.Format(_T("长度：%d"), ntohs(uh->udp_ulen));
			hItem = m_tree1.InsertItem(str, hSubItem);
			str.Format(_T("校验和：0x%x"), ntohs(uh->udp_checksum));
			hItem = m_tree1.InsertItem(str, hSubItem);
			if (ntohs(uh->udp_dport) == DNS || ntohs(uh->udp_sport) == DNS)
			{
				hSubItem = m_tree1.InsertItem(_T("应用层"), hRoot);
				dns_hdr* dh;
				const u_char* dns_data;
				dns_data = udp_data + 8;
				dh = (dns_hdr*)dns_data;
				str.Format(_T("标识：0x%x"), ntohs(dh->dns_id));
				hItem = m_tree1.InsertItem(str, hSubItem);
				str.Format(_T("标志：0x%x"), ntohs(dh->dns_flags));
				hItem = m_tree1.InsertItem(str, hSubItem);
				str.Format(_T("问题数：%d"), ntohs(dh->dns_qcount));
				hItem = m_tree1.InsertItem(str, hSubItem);
				str.Format(_T("资源记录数：%d"), ntohs(dh->dns_ancount));
				hItem = m_tree1.InsertItem(str, hSubItem);
				str.Format(_T("授权资源记录数：%d"), ntohs(dh->dns_nscount));
				hItem = m_tree1.InsertItem(str, hSubItem);
				str.Format(_T("额外资源记录数：%d"), ntohs(dh->dns_arcount));
				hItem = m_tree1.InsertItem(str, hSubItem);
			}
			break;
		}
		case TRANS_ICMP:
			{
			hItem = m_tree1.InsertItem(_T("上层协议:ICMP"), hSubItem);
			hSubItem = m_tree1.InsertItem(_T("传输层"), hRoot);
			icmp_hdr* icmph;
			const u_char* icmp_data;
			icmp_data = ip_data + ip_len;
			icmph = (icmp_hdr*)icmp_data;
			str.Format(_T("类型：%d"), icmph->icmp_type);
			hItem = m_tree1.InsertItem(str, hSubItem);
			str.Format(_T("代码：%d"), icmph->icmp_code);
			hItem = m_tree1.InsertItem(str, hSubItem);
			str.Format(_T("序列号：%d"), icmph->icmp_seq);
			hItem = m_tree1.InsertItem(str, hSubItem);
			str.Format(_T("校验和：0x%x"), ntohs(icmph->icmp_chksum));
			hItem = m_tree1.InsertItem(str, hSubItem);
			break;
			}
		}
		break;
	}
		case ARP:
		{
			hItem = m_tree1.InsertItem(_T("上层协议:ARP"), hSubItem);
			hSubItem = m_tree1.InsertItem(_T("网络层"), hRoot);
			arp_hdr* ah;
			const u_char* arp_data;
			arp_data = pkt_data + 14;
			ah = (arp_hdr*)arp_data;
			str.Format(_T("硬件类型：%d"), ntohs(ah->ar_hrd));
			hItem = m_tree1.InsertItem(str, hSubItem);
			str.Format(_T("协议类型：0x%x"), ntohs(ah->ar_pro));
			hItem = m_tree1.InsertItem(str, hSubItem);
			str.Format(_T("硬件长度：%d"), ah->ar_hln);
			hItem = m_tree1.InsertItem(str, hSubItem);
			str.Format(_T("协议长度：%d"), ah->ar_pln);
			hItem = m_tree1.InsertItem(str, hSubItem);
			str.Format(_T("操作类型：%d"), ntohs(ah->ar_op));
			hItem = m_tree1.InsertItem(str, hSubItem);
			str.Format(_T("发送端MAC地址：%x:%x:%x:%x:%x:%x"), ah->ar_srcmac[0], ah->ar_srcmac[1], ah->ar_srcmac[2], ah->ar_srcmac[3], ah->ar_srcmac[4], ah->ar_srcmac[5]);
			hItem = m_tree1.InsertItem(str, hSubItem);
			str.Format(_T("发送端协议地址：%d.%d.%d.%d"), ah->ar_srcip[0], ah->ar_srcip[1], ah->ar_srcip[2], ah->ar_srcip[3]);
			hItem = m_tree1.InsertItem(str, hSubItem);
			str.Format(_T("接收端MAC地址：%x:%x:%x:%x:%x:%x"), ah->ar_destmac[0], ah->ar_destmac[1], ah->ar_destmac[2], ah->ar_destmac[3], ah->ar_destmac[4], ah->ar_destmac[5]);
			hItem = m_tree1.InsertItem(str, hSubItem);
			str.Format(_T("接收端协议地址：%d.%d.%d.%d"), ah->ar_destip[0], ah->ar_destip[1], ah->ar_destip[2], ah->ar_destip[3]);
			hItem = m_tree1.InsertItem(str, hSubItem);
			break;
		}
		default:
			hItem = m_tree1.InsertItem(_T("上层协议:unknown"), hSubItem);
	}

	m_tree1.Expand(hRoot, TVE_EXPAND);		//默认展开目录
	m_tree1.Expand(hSubItem, TVE_EXPAND);

	//edit显示
	CString strHex;
	int nCount = 0;
	CString strText;

	for (unsigned short i = 0; i < pkt_header->caplen; i++)
	{
		CString hex;
		if ((i % 16) == 0)
		{
			//\x0d\x0a代表换行
			//"%04x"代表16进制格式的4位数
			hex.Format(_T("\x0d\x0a 0X%04x   "), nCount);  //转化为16进制    
			nCount++;
			if (i != 0)
			{
				strHex += _T("  "); //+ strText;
			}
			strHex += hex;
		}
		//
		hex.Format(_T("%2.2x "), pkt_data[i]);
		strHex += hex;
	}

	CStdioFile FileWrite;
	if (!(FileWrite.Open(_T("Record.txt"), CFile::modeWrite | CFile::typeText))) 
	{
		MessageBox(_T("Open Fail!"));
		return;
	}

	FileWrite.Seek(0, CFile::end);
	FileWrite.WriteString(strHex);
	FileWrite.WriteString(_T("\n"));
	FileWrite.Close();
	m_edit1.SetWindowText(strHex);
}


void CSnifferDlg::OnLvnItemchangedList1(NMHDR* pNMHDR, LRESULT* pResult)
{
	LPNMLISTVIEW pNMLV = reinterpret_cast<LPNMLISTVIEW>(pNMHDR);
	// TODO: 在此添加控件通知处理程序代码
	*pResult = 0;
	POSITION pos = m_list1.GetFirstSelectedItemPosition();
	if (pos == NULL)
		return;

	long index = m_list1.GetNextSelectedItem(pos);
	if (index < 0)
		return;

	ShowPacketTree(m_pktHeaders.GetAt(index), m_pktDatas.GetAt(index), index);
}


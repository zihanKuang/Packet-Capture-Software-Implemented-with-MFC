
// SnifferDlg.h: 头文件
//
#pragma warning(disable:4996)
#define _CRT_SECURE_NO_WARNING
#include <pcap.h>
#include "head.h"
#pragma once


// CSnifferDlg 对话框
class CSnifferDlg : public CDialogEx
{
// 构造
public:
	CSnifferDlg(CWnd* pParent = nullptr);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_SNIFFER_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()

public:
	CEdit m_edit1;
	CString m_tcpnum;
	CString m_udpnum;
	CString m_arpnum;
	CString m_icmpnum;
	CString m_dnsnum;
	CString m_totalnum;

	int tcpnum=0;
	int udpnum=0;
	int arpnum=0;
	int icmpnum=0;
	int dnsnum=0;
	int totalnum=0;

	CListCtrl m_list1;
	CTreeCtrl m_tree1;

	// 过滤
	char m_filtername[500];
	// 用于标记是否需要停止抓包
	BOOL m_shouldStop=0;
	// 线程句柄
	HANDLE m_hThread; 
	// 存储数据包的链表
	CPtrList m_localDataList;
	// char*链表，存储网络包数据
	CPtrList m_netDataList;		
	//抓包链表
	CPtrList pk_list;			
	// pcap 实例
	//pcap_t* m_adhandle;
	// 所有设备的列表
	pcap_if_t* m_allDevs= NULL;
	//选择的网卡
	pcap_if_t* m_pDevice = NULL;
	// 是否需要保存数据包到文件
	BOOL m_isNeedSaveFile;
	// 抓包数
	int n_pkt;		
	// 各类包计数结构体
	struct pktcount pkcount_T;	

	//保存捕获的数据包
	//CArray<Object,Objrct> Var1;
	//前一个参数是指定存储在数组中的对象的类型，后一个参数是指定用于访问存储在数组中对象的参数类型
	//其实这两个参数一般是一样的类型，程序中存储每次抓包的pkt_header和pkt_data
	CArray<const struct pcap_pkthdr*, const struct pcap_pkthdr*> m_pktHeaders;
	CArray<const u_char*, const u_char*> m_pktDatas;

	//pcap_dumper_t* myfile;//存储的文件

	//网卡选择
	afx_msg void OnAdp();
	//过滤选择
	afx_msg void OnFilter();
	//开始
	afx_msg void OnStart();
	//暂停
	afx_msg void OnStop();
	//保存
	afx_msg void OnSave();
	//int savefile();
	
	//list上面显示包内容
	void ShowPacketList(const pcap_pkthdr* pkt_header, const u_char* pkt_data);
	void ShowPacketTree(const pcap_pkthdr* pkt_header, const u_char* pkt_data, long index);
	afx_msg void OnLvnItemchangedList1(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnEnChangeEdit5();
};

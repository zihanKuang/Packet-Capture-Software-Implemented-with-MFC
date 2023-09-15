// CFilterDlg.cpp: 实现文件
//

#include "pch.h"
#include "Sniffer.h"
#include "CFilterDlg.h"
#include "CAdpDlg.h"
#include "afxdialogex.h"


// CFilterDlg 对话框

IMPLEMENT_DYNAMIC(CFilterDlg, CDialogEx)

CFilterDlg::CFilterDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_DIALOG2, pParent)
    , filtername(_T(""))
{
}

CFilterDlg::~CFilterDlg()
{
}

void CFilterDlg::DoDataExchange(CDataExchange* pDX)
{
    CDialogEx::DoDataExchange(pDX);
    DDX_Control(pDX, IDC_CHECK1, m_tcp);
    DDX_Control(pDX, IDC_CHECK2, m_udp);
    DDX_Control(pDX, IDC_CHECK3, m_arp);
    DDX_Control(pDX, IDC_CHECK4, m_icmp);
    DDX_Control(pDX, IDC_CHECK6, m_dns);
}


BEGIN_MESSAGE_MAP(CFilterDlg, CDialogEx)
    ON_BN_CLICKED(IDOK, &CFilterDlg::OnBnClickedOk)
END_MESSAGE_MAP()


// CFilterDlg 消息处理程序
BOOL CFilterDlg::OnInitDialog()
{
    CDialogEx::OnInitDialog();

    // TODO: Add extra initialization here
    m_tcp.SetCheck(1);
    m_udp.SetCheck(1);
    m_arp.SetCheck(1);
    m_icmp.SetCheck(1);
    m_dns.SetCheck(1);

    return TRUE;  // return TRUE unless you set the focus to a control
}

void CFilterDlg::OnBnClickedOk()
{
    // TODO: 在此添加控件通知处理程序代码
    if (1 == m_tcp.GetCheck())
    {
        filtername += _T("(tcp and ip) or ");
    }
    if (1 == m_udp.GetCheck())
    {
        filtername += _T("(udp and ip) or ");
    }
    if (1 == m_arp.GetCheck())
    {
        filtername += _T("arp or ");
    }
    if (1 == m_icmp.GetCheck())
    {
        filtername += _T("(icmp and ip) or ");
    }
    if (1 == m_dns.GetCheck())
    {
        filtername += _T("(udp and ip) and (dst port 53 or src port 53) or ");
    }

    // 如果至少有一个协议被选中，则删除最后的"or"字符串
    if (m_tcp.GetCheck() == 1 || m_udp.GetCheck() == 1 || m_arp.GetCheck() == 1 
        || m_icmp.GetCheck() == 1 || m_dns.GetCheck() == 1)
        filtername = filtername.Left(filtername.GetLength() - 4); 
    //注意去掉最后多余的" or ",否则过滤规则不成立

    // 关闭对话框
    CDialogEx::OnOK();
}

CString CFilterDlg::GetFilterName()
{
    return filtername;
}



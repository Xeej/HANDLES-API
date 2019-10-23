using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Runtime.InteropServices;
using System.Management;
using System.Diagnostics;

namespace WindowsFormsApp2_LAB_OS_2
{



    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }



        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true)]
        [PreserveSig]
        public static extern uint GetModuleFileName ([In]IntPtr hModule,[Out]StringBuilder lpFilename,[In][MarshalAs(UnmanagedType.U4)]int nSize);

        [DllImport("kernel32.dll")]
        static extern uint GetCurrentProcessId();

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll")]
        static extern uint GetLastError();

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool DuplicateHandle(
            [In] IntPtr hSourceProcessHandle,
            [In] IntPtr hSourceHandle,
            [In] IntPtr hTargetProcessHandle,
            [Out] out IntPtr lpTargetHandle,
            [In] int dwDesiredAccess,
            [In, MarshalAs(UnmanagedType.Bool)] bool bInheritHandle,
            [In] uint dwOptions);

        public enum ProcessAccessFlags : uint
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VirtualMemoryOperation = 0x00000008,
            VirtualMemoryRead = 0x00000010,
            VirtualMemoryWrite = 0x00000020,
            DuplicateHandle = 0x00000040,
            CreateProcess = 0x000000080,
            SetQuota = 0x00000100,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(
         ProcessAccessFlags processAccess,
          bool bInheritHandle,
             int processId);


        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hHandle);


        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESSENTRY32
        {
            public uint dwSize;
            public uint cntUsage;
            public uint th32ProcessID;
            public IntPtr th32DefaultHeapID;
            public uint th32ModuleID;
            public uint cntThreads;
            public uint th32ParentProcessID;
            public int pcPriClassBase;
            public uint dwFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szExeFile;
        };

        public struct THREADENTRY32

        {

            internal UInt32 dwSize;
            internal UInt32 cntUsage;
            internal UInt32 th32ThreadID;
            internal UInt32 th32OwnerProcessID;
            internal UInt32 tpBasePri;
            internal UInt32 tpDeltaPri;
            internal UInt32 dwFlags;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        public struct MODULEENTRY32
        {
            internal uint dwSize;
            internal uint th32ModuleID;
            internal uint th32ProcessID;
            internal uint GlblcntUsage;
            internal uint ProccntUsage;
            internal IntPtr modBaseAddr;
            internal uint modBaseSize;
            internal IntPtr hModule;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            internal string szModule;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            internal string szExePath;
        }

        [DllImport("kernel32.dll")]
        static extern bool Process32First(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("kernel32.dll")]
        static extern bool Thread32First(IntPtr hSnapshot, ref THREADENTRY32 lppe);

        [DllImport("kernel32.dll")]
        static extern bool Module32First(IntPtr hSnapshot, ref MODULEENTRY32 lpme);

        [DllImport("kernel32.dll")]
        static extern bool Process32Next(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("kernel32.dll")]
        static extern bool Thread32Next(IntPtr hSnapshot, ref THREADENTRY32 lppe);

        [DllImport("kernel32.dll")]
        static extern bool Module32Next(IntPtr hSnapshot, ref MODULEENTRY32 lpme);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateToolhelp32Snapshot(SnapshotFlags dwFlags, uint th32ProcessID);

        [Flags]
        public enum SnapshotFlags : uint
        {
            HeapList = 0x00000001,
            Process = 0x00000002,
            Thread = 0x00000004,
            Module = 0x00000008,
            Module32 = 0x00000010,
            All = (HeapList | Process | Thread | Module),
            Inherit = 0x80000000,
            NoHeaps = 0x40000000

        }

        IntPtr lpTargetHandle;
        uint dwOptions= 0x00000002;


        void add(ref ListBox listBox, PROCESSENTRY32 procEntry)
        {
            listBox.Items.Add("Размер: " + procEntry.dwSize.ToString());
            listBox.Items.Add("ID: " + procEntry.th32ProcessID.ToString());
            listBox.Items.Add("ID кучи: " + procEntry.th32DefaultHeapID.ToString());
            listBox.Items.Add("Потоки: " + procEntry.cntThreads.ToString());
            listBox.Items.Add("ID родителя: " + procEntry.th32ParentProcessID.ToString());
            listBox.Items.Add("Стандартный приоритет: " + procEntry.pcPriClassBase.ToString());
            listBox.Items.Add("Путь: " + procEntry.szExeFile.ToString());
            listBox.Items.Add("");
        }

        void addth(ref ListBox listBox, THREADENTRY32 Entry)
        {
            listBox.Items.Add("Размер: " + Entry.dwSize.ToString());
            listBox.Items.Add("Счетчик ссылок: " + Entry.cntUsage.ToString());
            listBox.Items.Add("ID: " + Entry.th32ThreadID.ToString());
            listBox.Items.Add("ID родителя: " + Entry.th32OwnerProcessID.ToString());
            listBox.Items.Add("ID приоритет: " + Entry.tpBasePri.ToString());
            listBox.Items.Add("");
        }

        void addMd(ref ListBox listBox, MODULEENTRY32 procEntry)
        {
            listBox.Items.Add("Размер: " + procEntry.dwSize.ToString());
            listBox.Items.Add("ID: " + procEntry.th32ProcessID.ToString());
            listBox.Items.Add("Счетчик загрузки: " + procEntry.ProccntUsage.ToString());
            listBox.Items.Add("Базовый адрес: " + procEntry.modBaseAddr.ToString());
            listBox.Items.Add("Размер: " + procEntry.modBaseSize.ToString());
            listBox.Items.Add("Дескриптор: " + ((uint)procEntry.hModule).ToString());
            listBox.Items.Add("Название модуля: " + procEntry.szModule.ToString());
            listBox.Items.Add("Путь к модулю: " + procEntry.szExePath.ToString());
            listBox.Items.Add("");
    }


        private void Form1_Load(object sender, EventArgs e)
        {
            textBox4.Text = GetCurrentProcessId().ToString();
            textBox5.Text = ((uint)GetCurrentProcess()).ToString("X");
            DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(), GetCurrentProcess(), out lpTargetHandle, 0, false, dwOptions);
            textBox6.Text = lpTargetHandle.ToString();
            int k = Convert.ToInt32(textBox4.Text);
            textBox7.Text = OpenProcess(ProcessAccessFlags.All, false, k).ToString();
            textBox8.Text = textBox6.Text;
           // CloseHandle(OpenProcess(ProcessAccessFlags.All, false, k));
            textBox9.Text = textBox7.Text;
            //CloseHandle(lpTargetHandle);


            IntPtr handleToSnapshot = IntPtr.Zero;
            PROCESSENTRY32 procEntry = new PROCESSENTRY32();
            procEntry.dwSize = (UInt32)Marshal.SizeOf(typeof(PROCESSENTRY32));
            handleToSnapshot = CreateToolhelp32Snapshot(SnapshotFlags.All, 0);

            Process32First(handleToSnapshot, ref procEntry);
            while (Process32Next(handleToSnapshot, ref procEntry))
                add(ref listBox1, procEntry);


            THREADENTRY32 Entry = new THREADENTRY32();
            Entry.dwSize = (UInt32)Marshal.SizeOf(typeof(THREADENTRY32));
            handleToSnapshot = CreateToolhelp32Snapshot(SnapshotFlags.All, 0);
            Thread32First(handleToSnapshot, ref Entry);

            while (Thread32Next(handleToSnapshot, ref Entry))
                if (Entry.th32OwnerProcessID == GetCurrentProcessId())
                    addth(ref listBox2, Entry);

            MODULEENTRY32 ModEntry = new MODULEENTRY32();
            ModEntry.dwSize = (UInt32)Marshal.SizeOf(typeof(MODULEENTRY32));
            handleToSnapshot = CreateToolhelp32Snapshot(SnapshotFlags.All, 0);
            bool f =Module32First(handleToSnapshot, ref ModEntry);

            
            while (Module32Next(handleToSnapshot, ref ModEntry))
                    addMd(ref listBox3, ModEntry);


        }

        private void button1_Click(object sender, EventArgs e)
        {
            IntPtr Mod = GetModuleHandle(textBox1.Text.ToString());

            StringBuilder fileName = new StringBuilder(255);
            GetModuleFileName(Mod, fileName, fileName.Capacity);

            textBox3.Text = Mod.ToString("X");
            textBox2.Text = fileName.ToString();
        }


    }
}

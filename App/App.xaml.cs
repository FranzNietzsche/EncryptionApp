using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Security.Cryptography;
using Windows.ApplicationModel;
using Windows.ApplicationModel.Activation;
using Windows.Foundation;
using Windows.Foundation.Collections;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Controls.Primitives;
using Windows.UI.Xaml.Data;
using Windows.UI.Xaml.Input;
using Windows.UI.Xaml.Media;
using Windows.UI.Xaml.Navigation;

namespace EncryptionApp
{
    /// <summary>
    /// 提供特定于应用程序的行为，以补充默认的应用程序类。
    /// </summary>
    sealed partial class App : Application
    {
        /// <summary>
        /// 初始化单一实例应用程序对象。这是执行的创作代码的第一行，
        /// 已执行，逻辑上等同于 main() 或 WinMain()。
        /// </summary>
        public App()
        {
            InitializeComponent();
            Suspending += OnSuspending;
        }

        /// <summary>
        /// 在应用程序由最终用户正常启动时进行调用。
        /// 将在启动应用程序以打开特定文件等情况下使用。
        /// </summary>
        /// <param name="e">有关启动请求和过程的详细信息。</param>
        protected override void OnLaunched(LaunchActivatedEventArgs e)
        {
            Frame rootFrame = Window.Current.Content as Frame;

            // 不要在窗口已包含内容时重复应用程序初始化，
            // 只需确保窗口处于活动状态
            if (rootFrame == null)
            {
                // 创建要充当导航上下文的框架，并导航到第一页
                rootFrame = new Frame();

                rootFrame.NavigationFailed += OnNavigationFailed;

                if (e.PreviousExecutionState == ApplicationExecutionState.Terminated)
                {
                    //TODO: 从之前挂起的应用程序加载状态
                }

                // 将框架放在当前窗口中
                Window.Current.Content = rootFrame;
            }

            if (e.PrelaunchActivated == false)
            {
                if (rootFrame.Content == null)
                {
                    // 当导航堆栈尚未还原时，导航到第一页，
                    // 并通过将所需信息作为导航参数传入来配置
                    // 参数
                    rootFrame.Navigate(typeof(MainPage), e.Arguments);
                }
                // 确保当前窗口处于活动状态
                Window.Current.Activate();
            }
        }

        /// <summary>
        /// 导航到特定页失败时调用
        /// </summary>
        ///<param name="sender">导航失败的框架</param>
        ///<param name="e">有关导航失败的详细信息</param>
        void OnNavigationFailed(object sender, NavigationFailedEventArgs e)
        {
            throw new Exception("Failed to load Page " + e.SourcePageType.FullName);
        }

        /// <summary>
        /// 在将要挂起应用程序执行时调用。  在不知道应用程序
        /// 无需知道应用程序会被终止还是会恢复，
        /// 并让内存内容保持不变。
        /// </summary>
        /// <param name="sender">挂起的请求的源。</param>
        /// <param name="e">有关挂起请求的详细信息。</param>
        private void OnSuspending(object sender, SuspendingEventArgs e)
        {
            var deferral = e.SuspendingOperation.GetDeferral();
            //TODO: 保存应用程序状态并停止任何后台活动
            deferral.Complete();
        }

        public static bool Equal(byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
                return false;
            else
                for (int i = 0; i < a.Length; i++)
                {
                    if (a[i] != b[i])
                        return false;
                }
            return true;
        }

        /*
        public static byte[] Read(Stream source)
        {
            byte[] text = new byte[source.Length];
            using (FileStream fileStream = new FileStream(filename, FileMode.Open, FileAccess.Read))
            {
                text = new byte[fileStream.Length];
                fileStream.Read(text, 0, text.Length);
            }
            source.ReadAsync(text, 0, text.Length);
            return text;
        }

        public static byte[] Read(Stream source, int blockSize, out byte[] hmac, out byte[] iv)
        {
            byte[] text = new byte[source.Length - 33 - blockSize];
            hmac = new byte[32];
            iv = new byte[blockSize];
            source.Read(hmac, 0, 32);
            source.Read(iv, 0, blockSize);
            source.Read(text, 0, text.Length);
            return text;
        }

        public static void Encrypt(Stream source, Stream destination, byte[] key, SymmetricAlgorithm algorithm)
        {
            byte[] plaintext = Read(source);
            source.Dispose();
            algorithm.Key = key;
            using (FileStream fileStream = new FileStream(cipherFile, FileMode.CreateNew, FileAccess.Write))
            {
                byte[] cipher = algorithm.CreateEncryptor().TransformFinalBlock(plaintext, 0, plaintext.Length);
                byte[] hmac = new HMACSHA256(key).ComputeHash(cipher);
                fileStream.Write(hmac, 0, hmac.Length);
                fileStream.Write(algorithm.IV, 0, algorithm.IV.Length);
                fileStream.Write(cipher, 0, cipher.Length);
            }
            byte[] cipher = algorithm.CreateEncryptor().TransformFinalBlock(plaintext, 0, plaintext.Length);
            byte[] hmac = new HMACSHA256(key).ComputeHash(cipher);
            destination.Write(hmac, 0, hmac.Length);
            destination.Write(algorithm.IV, 0, algorithm.IV.Length);
            destination.Write(cipher, 0, cipher.Length);
            destination.Dispose();
        }

        public static void Encrypt(Stream source, Stream destination, String password, int type)
        {
            SymmetricAlgorithm algorithm;
            if (type == 0)
                algorithm = Aes.Create();
            else
                algorithm = TripleDES.Create();
            byte[] plaintext = Read(source);
            source.Dispose();
            algorithm.Key = StringToBytes(password, algorithm);
            byte[] cipher = algorithm.CreateEncryptor().TransformFinalBlock(plaintext, 0, plaintext.Length);
            byte[] hmac = new HMACSHA256(algorithm.Key).ComputeHash(cipher);
            destination.Write(hmac, 0, hmac.Length);
            destination.Write(algorithm.IV, 0, algorithm.IV.Length);
            destination.Write(cipher, 0, cipher.Length);
            destination.Dispose();
        }

        public static bool Decrypt(Stream source, Stream destination, String password, int type)
        {
            SymmetricAlgorithm algorithm;
            if (type == 0)
                algorithm = Aes.Create();
            else
                algorithm = TripleDES.Create();
            byte[] cipher = Read(source, algorithm.BlockSize / 8, out byte[] hmac, out byte[] iv);
            source.Dispose();
            byte[] key = StringToBytes(password, algorithm);
            if (Equal(hmac, new HMACSHA256(key).ComputeHash(cipher)))
            {
                byte[] plaintext = algorithm.CreateDecryptor(key, iv).TransformFinalBlock(cipher, 0, cipher.Length);
                destination.Write(plaintext, 0, plaintext.Length);
                destination.Dispose();
                return true;
            }
            destination.Dispose();
            return false;
        }

        public static String Encrypt(String plaintext, byte[] key, SymmetricAlgorithm algorithm)
        {
            byte[] plainbyte = Encoding.UTF8.GetBytes(plaintext);
            algorithm.Key = key;
            return Encoding.UTF8.GetString(algorithm.CreateEncryptor().TransformFinalBlock(plainbyte, 0, plainbyte.Length));
        }

        public static String Decrypt(String ciphertext, byte[] key, SymmetricAlgorithm algorithm)
        {
            byte[] cipherbyte = Encoding.UTF8.GetBytes(ciphertext);
            algorithm.Key = key;
            return Encoding.UTF8.GetString(algorithm.CreateDecryptor().TransformFinalBlock(cipherbyte, 0, cipherbyte.Length));
        }
        */
        public static byte[] StringToBytes(String password, SymmetricAlgorithm algorithm)
        {
            List<byte> bytes = Encoding.UTF8.GetBytes(password).ToList();
            KeySizes size = algorithm.LegalKeySizes[0];
            if (bytes.Count * 8 < size.MinSize || (bytes.Count * 8 - size.MinSize) % size.SkipSize != 0)
                bytes.AddRange(new byte[(bytes.Count * 8 < size.MinSize ? size.MinSize / 8 : ((bytes.Count * 8 - size.MinSize) / size.SkipSize + 1) * size.SkipSize / 8 + size.MinSize / 8) - bytes.Count]);
            return bytes.ToArray();
        }
    }
}
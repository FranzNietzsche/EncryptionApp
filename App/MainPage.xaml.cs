using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Security.Cryptography;
using System.Text;
using Windows.ApplicationModel.DataTransfer;
using Windows.ApplicationModel.Email;
using Windows.Storage;
using Windows.Storage.Pickers;
using Windows.Storage.Streams;
using System.Threading.Tasks;
using Windows.Foundation;
using Windows.Foundation.Collections;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Controls.Primitives;
using Windows.UI.Xaml.Data;
using Windows.UI.Xaml.Input;
using Windows.UI.Xaml.Media;
using Windows.UI.Xaml.Media.Imaging;

// https://go.microsoft.com/fwlink/?LinkId=402352&clcid=0x804 上介绍了“空白页”项模板

namespace EncryptionApp
{
    /// <summary>
    /// 可用于自身或导航至 Frame 内部的空白页。
    /// </summary>
    public sealed partial class MainPage : Page
    {
        private ObservableCollection<Item> itemsToEncrypt = new ObservableCollection<Item>(), itemsToDecrypt = new ObservableCollection<Item>();
        private ObservableCollection<File> filesToHash = new ObservableCollection<File>();

        public MainPage()
        {
            InitializeComponent();
            ClearTemporyFiles();
            Windows.ApplicationModel.Core.CoreApplication.GetCurrentView().TitleBar.ExtendViewIntoTitleBar = true;
            Windows.UI.ViewManagement.ApplicationView.GetForCurrentView().TitleBar.ButtonBackgroundColor = Windows.UI.Colors.Transparent;
            Windows.UI.ViewManagement.ApplicationView.GetForCurrentView().TitleBar.ButtonInactiveBackgroundColor = Windows.UI.Colors.Transparent;
            Window.Current.SetTitleBar(title);
            if (ApplicationData.Current.LocalSettings.Values["Algorithm"] == null)
                ApplicationData.Current.LocalSettings.Values["Algorithm"] = 0;
            int i = (int)ApplicationData.Current.LocalSettings.Values["Algorithm"];
            tdes.IsChecked = i % 2 == 1;
            cts.IsChecked = (i >> 1) % 2 == 1;
            zeros.IsChecked = (i >> 2) % 2 == 1;
            sha1.IsChecked = (i >> 3) % 4 == 1;
            sha256.IsChecked = (i >> 3) % 4 == 2;
            DataTransferManager dataTransferManager = DataTransferManager.GetForCurrentView();
            dataTransferManager.DataRequested += DataTransferManager_DataRequested;
        }

        private async void AddFilesToEncryptAsync(object sender, RoutedEventArgs e)
        {
            FileOpenPicker openPicker = new FileOpenPicker();
            openPicker.FileTypeFilter.Add("*");
            IReadOnlyList<StorageFile> files = await openPicker.PickMultipleFilesAsync();
            if (files.Count > 0)
                foreach (StorageFile file in files)
                    itemsToEncrypt.Add(new Item(file));
        }

        private async void AddFolderToEncryptAsync(object sender, RoutedEventArgs e)
        {
            FolderPicker picker = new FolderPicker();
            picker.FileTypeFilter.Add("*");
            StorageFolder folder = await picker.PickSingleFolderAsync();
            if (folder != null)
            {
                itemsToEncrypt.Add(new Item(folder, true));
            }
        }

        private async void AddFilesToDecryptAsync(object sender, RoutedEventArgs e)
        {
            FileOpenPicker openPicker = new FileOpenPicker();
            openPicker.FileTypeFilter.Add("*");
            IReadOnlyList<StorageFile> files = await openPicker.PickMultipleFilesAsync();
            if (files.Count > 0)
            {
                foreach (StorageFile file in files)
                    itemsToDecrypt.Add(new Item(file));
            }
        }

        private async void AddFilesToHashAsync(object sender, RoutedEventArgs e)
        {
            FileOpenPicker openPicker = new FileOpenPicker();
            openPicker.FileTypeFilter.Add("*");
            IReadOnlyList<StorageFile> files = await openPicker.PickMultipleFilesAsync();
            if (files.Count > 0)
                foreach (StorageFile file in files)
                    filesToHash.Add(new File(file));
        }

        private void ClearItemsToEncrypt(object sender, RoutedEventArgs e)
        {
            itemsToEncrypt.Clear();
        }

        private void ClearItemsToDecrypt(object sender, RoutedEventArgs e)
        {
            itemsToDecrypt.Clear();
        }

        private void ClearItemsToHash(object sender, RoutedEventArgs e)
        {
            filesToHash.Clear();
        }

        private async void EncryptAsync(object sender, RoutedEventArgs e)
        {
            int setting = (int)ApplicationData.Current.LocalSettings.Values["Algorithm"] % 8;
            if (itemsToEncrypt.Count > 0)
                /*if (encryptionKey.Password.Length < 4)
                {
                    await new ContentDialog { Title = "The password's length mustn't be less than 4.", CloseButtonText = "OK" }.ShowAsync();
                }*/
                if (setting % 2 == 1 && TripleDES.IsWeakKey(App.StringToBytes(encryptionKey.Password, TripleDES.Create())))
                    await new ContentDialog { Title = "You are using a weak password for 3DES, please strengthen it.", CloseButtonText = "OK" }.ShowAsync();
                else
                {
                    FolderPicker folderPicker = new FolderPicker();
                    folderPicker.FileTypeFilter.Add("*");
                    StorageFolder folder = await folderPicker.PickSingleFolderAsync();
                    if (folder != null)
                    {
                        EnableButton(0, false);
                        SymmetricAlgorithm algorithm = Item.GetSymmetricAlgorithm(setting);
                        for (int i = 0; i < itemsToEncrypt.Count; i++)
                            UpdateItemsToEncrypt(i, folder, setting, algorithm);
                    }
                }
        }

        private async void DecryptAsync(object sender, RoutedEventArgs e)
        {
            if (itemsToDecrypt.Count > 0)
            {
                FolderPicker folderPicker = new FolderPicker();
                folderPicker.FileTypeFilter.Add("*");
                StorageFolder folder = await folderPicker.PickSingleFolderAsync();
                if (folder != null)
                {
                    EnableButton(1, false);
                    for (int i = 0; i < itemsToDecrypt.Count; i++)
                        UpdateItemsToDecrypt(i, folder);
                }
            }
        }

        public async void HashAsync(object sender, RoutedEventArgs e)
        {
            if (filesToHash.Count > 0)
            {
                EnableButton(3, false);
                foreach (File file in filesToHash)
                    await file.HashAsync();
                await result.ShowAsync();
                filesToHash.Clear();
                EnableButton(3, true);
            }
        }

        private void ChangeSetting(object sender, RoutedEventArgs e)
        {
            String group = (sender as RadioButton).GroupName;
            if (group == "A" && (int)ApplicationData.Current.LocalSettings.Values["Algorithm"] % 2 == 1 ^ BoolConvert(tdes.IsChecked))
                ApplicationData.Current.LocalSettings.Values["Algorithm"] = (int)ApplicationData.Current.LocalSettings.Values["Algorithm"] ^ 1;
            else if (group == "M" && ((int)ApplicationData.Current.LocalSettings.Values["Algorithm"] >> 1) % 2 == 1 ^ BoolConvert(cts.IsChecked))
                ApplicationData.Current.LocalSettings.Values["Algorithm"] = (int)ApplicationData.Current.LocalSettings.Values["Algorithm"] ^ 2;
            else if (group == "P" && ((int)ApplicationData.Current.LocalSettings.Values["Algorithm"] >> 2) % 2 == 1 ^ BoolConvert(zeros.IsChecked))
                ApplicationData.Current.LocalSettings.Values["Algorithm"] = (int)ApplicationData.Current.LocalSettings.Values["Algorithm"] ^ 4;
            else if (group == "H")
                if (BoolConvert(sha1.IsChecked))
                    ApplicationData.Current.LocalSettings.Values["Algorithm"] = (int)ApplicationData.Current.LocalSettings.Values["Algorithm"] % 8 + 8;
                else if (BoolConvert(sha256.IsChecked))
                    ApplicationData.Current.LocalSettings.Values["Algorithm"] = (int)ApplicationData.Current.LocalSettings.Values["Algorithm"] % 8 + 16;
                else
                    ApplicationData.Current.LocalSettings.Values["Algorithm"] = (int)ApplicationData.Current.LocalSettings.Values["Algorithm"] % 8;
        }

        private void Share(object sender, RoutedEventArgs e)
        {
            DataTransferManager.ShowShareUI();
        }

        private void DataTransferManager_DataRequested(DataTransferManager sender, DataRequestedEventArgs e)
        {
            //await Windows.System.Launcher.LaunchUriAsync(new Uri("ms-windows-store://pdp/?ProductId=9N8Q5MNH02DL"));
            e.Request.Data.SetWebLink(new Uri("https://www.microsoft.com/store/apps/9N8Q5MNH02DL"));
            e.Request.Data.Properties.Title = "Share this app";
        }
        
        private async void SendEmail(object sender, RoutedEventArgs e)
        {
            EmailMessage email = new EmailMessage();
            email.To.Add(new EmailRecipient("cruikai@outlook.com"));
            await EmailManager.ShowComposeNewEmailAsync(email);
        }

        private async void ClearTemporyFiles()
        {
            foreach (IStorageItem item in await ApplicationData.Current.TemporaryFolder.GetItemsAsync())
                await item.DeleteAsync();
        }

        private async void UpdateItemsToEncrypt(int i, StorageFolder folder, int setting, SymmetricAlgorithm algorithm)
        {
            Item currentItem = itemsToEncrypt[i];
            itemsToEncrypt[i] = currentItem.GetProcessingItem();
            itemsToEncrypt[i] = currentItem.GetFinishedItem(await currentItem.EncryptAsync(folder, encryptionKey.Password, setting, algorithm));
            if (itemsToEncrypt.All(x => !x.Processing))
            {
                foreach (IStorageItem item in await ApplicationData.Current.TemporaryFolder.GetItemsAsync())
                    await item.DeleteAsync();
                Windows.Storage.AccessCache.StorageApplicationPermissions.FutureAccessList.Clear();
                await new ContentDialog { Title = "Done.", Content = "Finished.", CloseButtonText = "OK" }.ShowAsync();
                itemsToEncrypt.Clear();
                EnableButton(0, true);
            }
        }

        private async void UpdateItemsToDecrypt(int i, StorageFolder folder)
        {
            Item currentItem = itemsToDecrypt[i];
            itemsToDecrypt[i] = currentItem.GetProcessingItem();
            itemsToDecrypt[i] = currentItem.GetFinishedItem(await currentItem.DecryptAsync(folder, decryptionKey.Password));
            if (itemsToDecrypt.All(x => !x.Processing))
            {
                Windows.Storage.AccessCache.StorageApplicationPermissions.FutureAccessList.Clear();
                await new ContentDialog { Title = "Done.", Content = "Finished.", CloseButtonText = "OK" }.ShowAsync();
                itemsToDecrypt.Clear();
                EnableButton(1, true);
            }
        }

        private void EnableButton(int type, bool enabled)
        {
            if (type == 0)
            {
                add.IsEnabled = enabled;
                add2.IsEnabled = enabled;
                clear.IsEnabled = enabled;
                encryption.IsEnabled = enabled;
            }
            else if (type == 1)
            {
                add3.IsEnabled = enabled;
                clear2.IsEnabled = enabled;
                decryption.IsEnabled = enabled;
            }
            else
            {
                add4.IsEnabled = enabled;
                clear3.IsEnabled = enabled;
                hash.IsEnabled = enabled;
            }
        }

        public static bool BoolConvert(bool? source)
        {
            if (source.HasValue)
                return (bool)source;
            return false;
        }
    }

    public class Item
    {
        private int size = 65536;
        private readonly Task<Stream> OpenStreamAsync;
        private readonly bool compressed;
        public bool Processing { get; private set; }
        public Visibility Finished { get; private set; } = Visibility.Collapsed;
        public Symbol Result { get; private set; }
        public BitmapImage Icon { get; } = new BitmapImage();
        public String Directory { get; private set; }
        public String Name { get; private set; }

        public Item(IStorageItem item, bool compressed = false)
        {
            this.compressed = compressed;
            GetThumbnailAsync(item as IStorageItemProperties);
            Directory = Path.GetDirectoryName(item.Path);
            Name = item.Name;
            OpenStreamAsync = compressed ? CompressAsync(item as StorageFolder) : (item as StorageFile).OpenStreamForReadAsync();
            
        }

        public Item GetProcessingItem()
        {
            Processing = true;
            return this;
        }

        public Item GetFinishedItem(bool success)
        {
            Processing = false;
            Finished = Visibility.Visible;
            Result = success ? Symbol.Accept : Symbol.Cancel;
            return this;
        }

        public static async Task<Stream> CompressAsync(StorageFolder folder)
        {
            Windows.Storage.AccessCache.StorageApplicationPermissions.FutureAccessList.Add(folder);
            String filename = Guid.NewGuid().ToString();
            await Task.Run(() => ZipFile.CreateFromDirectory(folder.Path, ApplicationData.Current.TemporaryFolder.Path + "\\" + filename, CompressionLevel.Fastest, true));
            return await (await ApplicationData.Current.TemporaryFolder.GetFileAsync(filename)).OpenStreamForReadAsync();
        }

        public async Task<bool> EncryptAsync(StorageFolder folder, String password, int setting, SymmetricAlgorithm algorithm)
        {
            StorageFile file = await folder.CreateFileAsync(Name, CreationCollisionOption.GenerateUniqueName);
            using (Stream source = await OpenStreamAsync)
            using (Stream destination = await file.OpenStreamForWriteAsync())
            {
                algorithm.Key = App.StringToBytes(password, algorithm);
                destination.Write(new byte[32], 0, 32);
                destination.WriteByte((byte)(compressed ? setting : setting ^ 8));
                destination.Write(algorithm.IV, 0, algorithm.IV.Length);
                using (CryptoStream stream = new CryptoStream(source, algorithm.CreateEncryptor(), CryptoStreamMode.Read))
                    for (byte[] cipher = new byte[size]; (size = stream.Read(cipher, 0, size)) > 0; destination.Write(cipher, 0, size)) ;
            }
            byte[] hmac;
            using (Stream destination = await file.OpenStreamForReadAsync())
            {
                destination.Seek(32, SeekOrigin.Begin);
                hmac = new HMACSHA256(Encoding.UTF8.GetBytes(password)).ComputeHash(destination);
            }
            using (Stream destination = await file.OpenStreamForWriteAsync())
                destination.Write(hmac, 0, hmac.Length);
            return true;
        }

        public async Task<bool> DecryptAsync(StorageFolder folder, String password)
        {
            using (Stream source = await OpenStreamAsync)
            {
                byte[] hmac = new byte[32];
                source.Read(hmac, 0, 32);
                if (App.Equal(hmac, new HMACSHA256(Encoding.UTF8.GetBytes(password)).ComputeHash(source)))
                {
                    source.Seek(32, SeekOrigin.Begin);
                    int setting = source.ReadByte();
                    SymmetricAlgorithm algorithm = GetSymmetricAlgorithm(setting);
                    byte[] iv = new byte[algorithm.BlockSize / 8];
                    source.Read(iv, 0, algorithm.BlockSize / 8);
                    byte[] key = App.StringToBytes(password, algorithm);
                    if (setting / 8 == 0)
                    {
                        Windows.Storage.AccessCache.StorageApplicationPermissions.FutureAccessList.Add(folder);
                        StorageFile zipFile = await ApplicationData.Current.TemporaryFolder.CreateFileAsync(Guid.NewGuid().ToString());
                        using (Stream zipStream = await zipFile.OpenStreamForWriteAsync())
                        using (CryptoStream stream = new CryptoStream(source, algorithm.CreateDecryptor(key, iv), CryptoStreamMode.Read))
                            for (byte[] plaintext = new byte[size]; (size = stream.Read(plaintext, 0, size)) > 0; zipStream.Write(plaintext, 0, size)) ;
                        using (ZipArchive zipArchive = ZipFile.OpenRead(zipFile.Path))
                            for (bool breaking = false; !breaking;)
                                if ((await folder.TryGetItemAsync(zipArchive.Entries[0].ToString().Split('/')[0])) == null)
                                {
                                    await Task.Run(() => zipArchive.ExtractToDirectory(folder.Path));
                                    breaking = true;
                                }
                                else
                                {
                                    ContentDialog dialog = new ContentDialog { Title = "File names conflict in destination directory", Content = Name, PrimaryButtonText = "Retry", SecondaryButtonText = "Ignore" };
                                    dialog.PrimaryButtonClick += (sender, e) => { breaking = false; };
                                    dialog.SecondaryButtonClick += (sender, e) => { breaking = true; };
                                    await dialog.ShowAsync();
                                    if (breaking)
                                        return false;
                                }
                        await zipFile.DeleteAsync();
                    }
                    else
                        using (Stream destination = await folder.OpenStreamForWriteAsync(Name, CreationCollisionOption.GenerateUniqueName))
                        using (CryptoStream stream = new CryptoStream(source, algorithm.CreateDecryptor(key, iv), CryptoStreamMode.Read))
                            for (byte[] plaintext = new byte[size]; (size = stream.Read(plaintext, 0, size)) > 0; destination.Write(plaintext, 0, size)) ;
                    return true;
                }
                return false;
            }
        }

        public static SymmetricAlgorithm GetSymmetricAlgorithm(int i)
        {
            SymmetricAlgorithm algorithm;
            if (i % 2 == 0)
                algorithm = Aes.Create();
            else
                algorithm = TripleDES.Create();
            algorithm.Mode = (i >> 1) % 2 == 0 ? CipherMode.CBC : CipherMode.CTS;
            algorithm.Padding = (i >> 2) % 2 == 0 ? PaddingMode.PKCS7 : PaddingMode.Zeros;
            return algorithm;
        }

        private async Task<Stream> TryOpenStreamAsync()
        {
            for (bool breaking = false; !breaking;)
                try
                {
                    return await OpenStreamAsync;
                }
                catch (Exception exception)
                {
                    ContentDialog dialog = new ContentDialog { Title = "Error occurred in "+Name, Content = exception.Message, PrimaryButtonText = "Retry", SecondaryButtonText = "Ignore" };
                    dialog.PrimaryButtonClick += (sender, e) => { breaking = false; };
                    dialog.SecondaryButtonClick += (sender, e) => { breaking = true; };
                    await dialog.ShowAsync();
                }
            return null;
        }

        private async void GetThumbnailAsync(IStorageItemProperties item)
        {
            using (InMemoryRandomAccessStream stream = new InMemoryRandomAccessStream())
            {
                try
                {
                    await RandomAccessStream.CopyAsync(await item.GetThumbnailAsync(Windows.Storage.FileProperties.ThumbnailMode.SingleItem), stream);
                }
                catch
                {
                    await RandomAccessStream.CopyAsync(await item.GetThumbnailAsync(Windows.Storage.FileProperties.ThumbnailMode.SingleItem), stream);
                }
                stream.Seek(0);
                Icon.SetSource(stream);
            }
        }
    }

    public class File
    {
        private readonly Task<Stream> OpenStreamAsync;
        public BitmapImage Icon { get; } = new BitmapImage();
        public String Directory { get; private set; }
        public String Name { get; private set; }
        public String Value { get; private set; }

        public File(StorageFile file)
        {
            GetThumbnailAsync(file);
            Directory = Path.GetDirectoryName(file.Path);
            Name = file.Name;
            OpenStreamAsync = file.OpenStreamForReadAsync();
        }

        public async Task HashAsync()
        {
            int setting = ((int)ApplicationData.Current.LocalSettings.Values["Algorithm"] >> 3) % 4;
            HashAlgorithm algorithm;
            if (setting == 0)
                algorithm = MD5.Create();
            else if (setting == 1)
                algorithm = SHA1.Create();
            else
                algorithm = SHA256.Create();
            using (Stream source = await OpenStreamAsync)
                Value = BitConverter.ToString(algorithm.ComputeHash(source)).Replace("-", "");
        }

        private async void GetThumbnailAsync(StorageFile file)
        {
            using (InMemoryRandomAccessStream stream = new InMemoryRandomAccessStream())
            {
                try
                {
                    await RandomAccessStream.CopyAsync(await file.GetThumbnailAsync(Windows.Storage.FileProperties.ThumbnailMode.SingleItem), stream);
                }
                catch
                {
                    await RandomAccessStream.CopyAsync(await file.GetThumbnailAsync(Windows.Storage.FileProperties.ThumbnailMode.SingleItem), stream);
                }
                stream.Seek(0);
                Icon.SetSource(stream);
            }
        }
    }
}

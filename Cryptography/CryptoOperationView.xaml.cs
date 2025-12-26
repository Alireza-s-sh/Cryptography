using Cryptography.Enums;
using Cryptography.Models;
using Cryptography.Views;
using Microsoft.Win32;
using System.Collections.ObjectModel;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;

namespace Cryptography
{
    public partial class CryptoOperationView : UserControl
    {
        private readonly CryptoService _crypto = new CryptoService();
        private ObservableCollection<string> _logEntries = new ObservableCollection<string>();
        private int _logCount = 0;
        private bool _autoScrollEnabled = true;
        private EncryptionMethod _selectedEncryptionMethod = EncryptionMethod.SecureEnvelope;
        private string _currentAlg = "AES"; // مقدار پیش‌فرض مطابق XAML
        private string _currentMode = "CBC"; // مقدار پیش‌فرض مطابق XAML

        // کلیدها توسط MainWindow ست می‌شوند
        public KeyModel MyKeys { get; set; }
        public KeyModel TargetKeys { get; set; }

        public CryptoOperationView()
        {
            InitializeComponent();
            LogItemsControl.ItemsSource = _logEntries;
        }

        // متدی برای تنظیم حالت Producer یا Consumer
        public void ConfigureView(bool isConsumerMode, KeyModel myKeys, KeyModel targetKeys)
        {
            MyKeys = myKeys;
            TargetKeys = targetKeys;

            if (isConsumerMode)
            {
                // 🔵 حالت Consumer
                // فقط دکمه Decrypt باشد، Encrypt نباشد
                EncryptActionPanel.Visibility = Visibility.Collapsed;
                DecryptBtn.Visibility = Visibility.Visible;

                GenerateKeyBtn.Visibility = Visibility.Collapsed;
                AppendLog("🔵 Consumer Mode Activated (Decrypt Only)");
            }
            else
            {
                // 🟠 حالت Producer
                // فقط دکمه Encrypt باشد، Decrypt نباشد
                EncryptActionPanel.Visibility = Visibility.Visible;
                DecryptBtn.Visibility = Visibility.Collapsed; // ✅ دکمه دیکریپت حذف شد

                GenerateKeyBtn.Visibility = Visibility.Visible;
                AppendLog("🟠 Producer Mode Activated");
            }
        }

        private void BrowseBtn_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new OpenFileDialog();
            dlg.Title = "Select input file";
            if (dlg.ShowDialog() == true)
            {
                FilePathText.Text = dlg.FileName;
                AppendLog($"Selected: {dlg.FileName}");
            }
        }

        private async void EncryptBtn_Click(object sender, RoutedEventArgs e)
        {
            var path = FilePathText.Text;
            if (!File.Exists(path)) { AppendLog("No valid input file selected."); return; }

            AppendLog("Starting encryption...");
            try
            {
                var key = KeyBox.Text;
                var alg = SelectedAlg();
                var mode = SelectedMode();

                // در حالت Producer: با کلید عمومی هدف (Target/Consumer) رمز می‌کنیم
                // و با کلید خصوصی خودمان (My/Producer) امضا می‌کنیم
                await Task.Run(() =>
                _crypto.EncryptFile(
                    path, key, alg, mode,
                    TargetKeys.PublicKey,
                    MyKeys.PrivateKey,
                    _selectedEncryptionMethod));

                AppendLog("✅ Encryption completed successfully!");
            }
            catch (Exception ex) { AppendLog("Error: " + ex.Message); }
        }

        private async void DecryptBtn_Click(object sender, RoutedEventArgs e)
        {
            var path = FilePathText.Text;
            if (!File.Exists(path)) { AppendLog("No valid input file selected."); return; }

            AppendLog("Starting decryption...");
            try
            {
                var key = KeyBox.Text;
                var mode = SelectedMode();

                // در حالت Consumer: با کلید خصوصی خودمان (My/Consumer) باز می‌کنیم
                // و با کلید عمومی هدف (Target/Producer) امضا را چک می‌کنیم
                await Task.Run(() => _crypto.DecryptFile(
                    path, SelectedAlg(), mode,
                    MyKeys.PrivateKey,
                    TargetKeys.PublicKey,
                    key));

                AppendLog("Decryption finished.");
            }
            catch (Exception ex) { AppendLog("Error: " + ex.Message); }
        }

        // --- سایر متدها دقیقاً مثل قبل ---
        private void GenerateKey_Click(object sender, RoutedEventArgs e)
        {
            var alg = SelectedAlg();
            KeyBox.Text = _crypto.GenerateRandomKey(alg);
            AppendLog($"🔑 {alg} key generated successfully");
            UpdateSystemStatus();
        }

        private void ImportKey_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new OpenFileDialog();
            if (dlg.ShowDialog() == true)
            {
                KeyBox.Text = File.ReadAllText(dlg.FileName);
                AppendLog($"Imported key from {dlg.FileName}");
            }
        }

        private void SaveKey_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new SaveFileDialog();
            if (dlg.ShowDialog() == true)
            {
                File.WriteAllText(dlg.FileName, KeyBox.Text);
                AppendLog($"Saved key to {dlg.FileName}");
            }
        }

        private void PasswordKey_Click(object sender, RoutedEventArgs e)
        {
            var pw = PromptForPassword();
            if (!string.IsNullOrEmpty(pw))
            {
                var alg = SelectedAlg();
                //var password = PromptForPassword(); // تابع ساده که یه InputBox نشون بده
                KeyBox.Text = _crypto.DeriveKeyFromPassword(pw, alg);
                AppendLog("Derived key from password.");
            }
        }
        private string PromptForPassword()
        {
            var dialog = new PasswordDialog
            {
               Owner= Window.GetWindow(this)
            };

            bool? result = dialog.ShowDialog();

            return result == true ? dialog.PasswordValue : string.Empty;
        }
        private string SelectedAlg()
        {
            return _currentAlg;
        }

        private string SelectedMode()
        {
            return _currentMode;
        }

        private void AppendLog(string text)
        {
            Dispatcher.Invoke(() =>
            {
                _logEntries.Add($"[{DateTime.Now:HH:mm:ss}] {text}");
                _logCount++;
                LogStats.Text = $"{_logCount} entries";
                if (_autoScrollEnabled) ScrollToEndDelayed();
            });
        }

        private async void ScrollToEndDelayed()
        {
            await Task.Delay(200);
            await Dispatcher.InvokeAsync(() => LogScroll.ScrollToEnd());
        }

        private void LogScroll_ScrollChanged(object sender, ScrollChangedEventArgs e)
        {
            if (e.ExtentHeightChange == 0)
                _autoScrollEnabled = Math.Abs(LogScroll.VerticalOffset - LogScroll.ScrollableHeight) < 1.0;
        }

        private void ClearLogBtn_Click(object sender, RoutedEventArgs e) { _logEntries.Clear(); _logCount = 0; }

        private void CopyLogBtn_Click(object sender, RoutedEventArgs e) { Clipboard.SetText(string.Join(Environment.NewLine, _logEntries)); }

        private void Algorithm_Checked(object sender, RoutedEventArgs e)
        {
            // هر وقت رادیویی تیک خورد، مقدارش را ذخیره کن
            if (sender is RadioButton rb && rb.IsChecked == true)
            {
                _currentAlg = rb.Content.ToString();
                UpdateSystemStatus();
            }
        }
        private void Mode_Checked(object sender, RoutedEventArgs e)
        {
            if (sender is RadioButton rb && rb.IsChecked == true)
            {
                _currentMode = rb.Content.ToString();
                UpdateSystemStatus();
            }
        }

        private void UpdateSystemStatus()
        {
            if (Alg_Status == null) return;
            Alg_Status.Text = $"Algorithm: {SelectedAlg()}";
            Mode_Status.Text = $"Mode: {SelectedMode()}";
            Key_Status.Text = $"Key: {KeyBox.Text}";
        }

        private void EncryptMethodBtn_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.ContextMenu != null)
            {
                btn.ContextMenu.PlacementTarget = btn;
                btn.ContextMenu.IsOpen = true;
            }
        }

        private void SelectSecureEnvelope(object sender, RoutedEventArgs e) => SetEncryptionMethod(EncryptionMethod.SecureEnvelope, "Secure Envelope");
        private void SelectSymmetric(object sender, RoutedEventArgs e) => SetEncryptionMethod(EncryptionMethod.SymmetricEncryption, "Symmetric");
        private void SelectRsaDirect(object sender, RoutedEventArgs e) => SetEncryptionMethod(EncryptionMethod.RSADirect, "RSA Direct");

        private void SetEncryptionMethod(EncryptionMethod method, string displayName)
        {
            _selectedEncryptionMethod = method;
            EncryptionMethodText.Text = displayName;
        }

        
    }
}
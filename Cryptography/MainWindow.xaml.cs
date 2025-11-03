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
    public partial class MainWindow : Window
    {
        private readonly CryptoService _crypto = new CryptoService();
        private ObservableCollection<string> _logEntries = new ObservableCollection<string>();
        private int _logCount = 0;
        private bool _autoScrollEnabled = true;
        public MainWindow()
        {
            InitializeComponent();
            LogItemsControl.ItemsSource = _logEntries;
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
            if (!File.Exists(path))
            {
                AppendLog("No valid input file selected.");
                return;
            }

            AppendLog("Starting encryption...");
            try
            {
                var key = KeyBox.Text; // 🔹 مقدار رو از UI بگیر قبل از Task.Run
                var alg = SelectedAlg();
                var mode = SelectedMode();
                AppendLog($"selected Algorithm: {alg}, selected Mode: {mode}");
                await Task.Run(() => _crypto.EncryptFile(path, key, alg, mode));

                AppendLog("✅ Encryption completed successfully!\n");
            }
            catch (Exception ex)
            {
                AppendLog("Error: " + ex.Message);
            }
        }

        private async void DecryptBtn_Click(object sender, RoutedEventArgs e)
        {
            var path = FilePathText.Text;
            if (!File.Exists(path))
            {
                AppendLog("No valid input file selected.");
                return;
            }

            AppendLog("Starting decryption...");
            try
            {
                var key = KeyBox.Text;
                var mode = SelectedMode();
                await Task.Run(() => _crypto.DecryptFile(path, key, SelectedAlg(), mode));
                AppendLog("Decryption finished.");
            }
            catch (Exception ex)
            {
                AppendLog("Error: " + ex.Message);
            }
        }

        private void GenerateKey_Click(object sender, RoutedEventArgs e)
        {
            var alg = SelectedAlg(); // از همون لیست الگوریتم انتخاب شده
            KeyBox.Text = _crypto.GenerateRandomKey(alg);
            AppendLog($"🔑 {alg} key generated successfully");
            UpdateSystemStatus();
        }

        private void ImportKey_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new OpenFileDialog();
            dlg.Title = "Import key file";
            if (dlg.ShowDialog() == true)
            {
                var txt = File.ReadAllText(dlg.FileName);
                KeyBox.Text = txt;
                AppendLog($"Imported key from {dlg.FileName}");
            }
        }

        private void SaveKey_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new SaveFileDialog();
            dlg.Title = "Save key";
            dlg.FileName = "key.txt";
            if (dlg.ShowDialog() == true)
            {
                File.WriteAllText(dlg.FileName, KeyBox.Text);
                AppendLog($"Saved key to {dlg.FileName}");
            }
        }

        private void PasswordKey_Click(object sender, RoutedEventArgs e)
        {
            //var pw = Microsoft.VisualBasic.Interaction.InputBox("Enter password to derive key:", "Password to Key", "");
            var pw = PromptForPassword();
            if (!string.IsNullOrEmpty(pw))
            {
                var alg = SelectedAlg();
                //var password = PromptForPassword(); // تابع ساده که یه InputBox نشون بده
                KeyBox.Text = _crypto.DeriveKeyFromPassword(pw, alg);
                AppendLog("Derived key from password.");
            }
        }

        private string SelectedAlg()
        {
            // Check if we're on the UI thread, if not, invoke on UI thread
            if (this.Dispatcher.CheckAccess())
            {
                // We're on UI thread - proceed normally
                foreach (var child in FindVisualChildren<RadioButton>(this))
                {
                    if (child.GroupName == "Algorithms" && child.IsChecked == true)
                        return child.Content?.ToString() ?? "AES";
                }
                return "AES"; // مقدار پیش‌فرض
            }
            else
            {
                // Invoke on UI thread
                return this.Dispatcher.Invoke(() => SelectedAlg());
            }
        }

        private string SelectedMode()
        {
            foreach (var child in FindVisualChildren<RadioButton>(this))
            {
                if (child.GroupName == "Modes" && child.IsChecked == true)
                    return child.Content.ToString() ?? "CBC";
            }
            return "CBC"; // مقدار پیش‌فرض
        }

        

        private void AppendLog(string text)
        {
            Dispatcher.Invoke(() =>
            {
                string timestamp = DateTime.Now.ToString("HH:mm:ss");
                string logEntry = $"[{timestamp}] {text}";

                _logEntries.Add(logEntry);
                _logCount++;
                LogStats.Text = $"{_logCount} entries";

                if (_autoScrollEnabled)
                {
                    ScrollToEndDelayed();
                }
            });
        }

        private async void ScrollToEndDelayed()
        {
            await Task.Delay(200); // Wait for UI to update
            await Dispatcher.InvokeAsync(() =>
            {
                LogScroll.ScrollToEnd();
            });
        }

        // Optional: Handle scroll events to disable auto-scroll when user manually scrolls
        private void LogScroll_ScrollChanged(object sender, ScrollChangedEventArgs e)
        {
            if (e.ExtentHeightChange == 0)
            {
                // User is scrolling manually
                _autoScrollEnabled = Math.Abs(LogScroll.VerticalOffset - LogScroll.ScrollableHeight) < 1.0;
            }

            if (e.ExtentHeightChange != 0 && _autoScrollEnabled)
            {
                // Content changed and auto-scroll is enabled
                LogScroll.ScrollToVerticalOffset(LogScroll.ExtentHeight);
            }
        }

        private void ClearLogBtn_Click(object sender, RoutedEventArgs e)
        {
            _logEntries.Clear();
            _logCount = 0;
            LogStats.Text = "Log cleared";
        }

        private void CopyLogBtn_Click(object sender, RoutedEventArgs e)
        {
            string allLogs = string.Join(Environment.NewLine, _logEntries);
            Clipboard.SetText(allLogs);

            // Show temporary feedback
            LogStats.Text = "Log copied to clipboard!";
            DispatcherTimer timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
            timer.Tick += (s, args) =>
            {
                timer.Stop();
                LogStats.Text = $"{_logCount} entries";
            };
            timer.Start();
        }

        // Additional method for different log levels with colors
        private void AppendLogWithLevel(string text, string level = "INFO")
        {
            string color = level switch
            {
                "ERROR" => "#FF6B6B",
                "WARN" => "#FFA500",
                "SUCCESS" => "#4ECDC4",
                "DEBUG" => "#8884FF",
                _ => "#B8D4FF" // INFO
            };

            Dispatcher.InvokeAsync(() =>
            {
                string timestamp = DateTime.Now.ToString("HH:mm:ss");
                string logEntry = $"[{timestamp}] [{level}] {text}";

                // For colored logs, you might want to use a more advanced approach
                // with a custom class instead of just strings
                _logEntries.Add(logEntry);
                _logCount++;
                LogStats.Text = $"{_logCount} entries";

                Dispatcher.InvokeAsync(() => LogScroll.ScrollToEnd(),
                    System.Windows.Threading.DispatcherPriority.Background);
            });
        }
        private string PromptForPassword()
        {
            var dialog = new PasswordDialog
            {
                Owner = this
            };

            bool? result = dialog.ShowDialog();

            return result == true ? dialog.PasswordValue : string.Empty;
        }
        private static List<T> FindVisualChildren<T>(DependencyObject depObj) where T : DependencyObject
        {
            var results = new List<T>();

            if (depObj == null) return results;

            if (!depObj.Dispatcher.CheckAccess())
            {
                // Invoke on UI thread and return results
                depObj.Dispatcher.Invoke(() =>
                {
                    results = FindVisualChildren<T>(depObj).ToList();
                });
                return results;
            }

            // We're on UI thread - proceed normally
            for (int i = 0; i < VisualTreeHelper.GetChildrenCount(depObj); i++)
            {
                var child = VisualTreeHelper.GetChild(depObj, i);
                if (child is T t)
                    results.Add(t);

                results.AddRange(FindVisualChildren<T>(child));
            }

            return results;
        }
        private void Algorithm_Checked(object sender, RoutedEventArgs e)
        {
            UpdateSystemStatus();
        }

        private void Mode_Checked(object sender, RoutedEventArgs e)
        {
            UpdateSystemStatus();
        }

        private void UpdateSystemStatus()
        {
            if (Alg_Status == null || Mode_Status == null || Key_Status == null)
                return;
            string alg = SelectedAlg();
            string mode = SelectedMode();
            var key = KeyBox.Text;
            Alg_Status.Text = $"Algorithm: {alg}";
            Mode_Status.Text = $"Mode: {mode}";
            Key_Status.Text = $"Key: {key}";
        }

    }
}

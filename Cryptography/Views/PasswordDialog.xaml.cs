using System.Windows;

namespace Cryptography.Views
{
    public partial class PasswordDialog : Window
    {
        public string PasswordValue { get; private set; } = "";

        public PasswordDialog()
        {
            InitializeComponent();
        }

        private void OkBtn_Click(object sender, RoutedEventArgs e)
        {
            PasswordValue = PasswordBox.Password;
            DialogResult = true;
        }

        private void CancelBtn_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
        }
    }
}

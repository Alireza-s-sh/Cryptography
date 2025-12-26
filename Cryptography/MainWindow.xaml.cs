using Cryptography.Models;
using System.Windows;
using System.Windows.Media;

namespace Cryptography
{
    public partial class MainWindow : Window
    {
        private KeyModel _producerKeys;
        private KeyModel _consumerKeys;
        private const string ProducerFileName = "producer.json";
        private const string ConsumerFileName = "consumer.json";

        public MainWindow()
        {
            InitializeComponent();
            LoadKeys();

            // تنظیم ویوی Producer
            // من پرودیوسر هستم: کلید من = ProducerKey، کلید هدف = ConsumerKey
            ProducerView.ConfigureView(isConsumerMode: false, myKeys: _producerKeys, targetKeys: _consumerKeys);

            // تنظیم ویوی Consumer
            // من کانسومر هستم: کلید من = ConsumerKey، کلید هدف = ProducerKey
            ConsumerView.ConfigureView(isConsumerMode: true, myKeys: _consumerKeys, targetKeys: _producerKeys);
        }

        private void LoadKeys()
        {
            var keyManager = new KeyManager();
            try
            {
                _producerKeys = keyManager.LoadOrCreateKeys(ProducerFileName);
                _consumerKeys = keyManager.LoadOrCreateKeys(ConsumerFileName);
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error loading keys: " + ex.Message);
            }
        }

        private void SwitchToProducer(object sender, RoutedEventArgs e)
        {
            ContentTabs.SelectedIndex = 0;

            // استایل دکمه‌ها
            BtnProducer.Background = Brushes.White;
            BtnProducer.Foreground = Brushes.Black;

            BtnConsumer.Background = Brushes.Transparent;
            BtnConsumer.Foreground = Brushes.White;
        }

        private void SwitchToConsumer(object sender, RoutedEventArgs e)
        {
            ContentTabs.SelectedIndex = 1;

            // استایل دکمه‌ها
            BtnConsumer.Background = Brushes.White;
            BtnConsumer.Foreground = Brushes.Black;

            BtnProducer.Background = Brushes.Transparent;
            BtnProducer.Foreground = Brushes.White;
        }
    }
}
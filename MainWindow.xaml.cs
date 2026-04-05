using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Numerics;

namespace _7._2_Aleksyuk_Khachatryan
{
    /// <summary>
    /// Логика взаимодействия для MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private RSACipher.RSAKeys _currentKeys;

        public MainWindow()
        {
            InitializeComponent();
        }

        /// <summary>
        /// Генерация ключей RSA и вывод их статуса.
        /// </summary>
        /// <param name="sender">Объект, вызвавший событие (кнопка генерации).</param>
        /// <param name="e">Параметры события маршрутизации.</param>
        private void GenerateKeys_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                _currentKeys = RSACipher.GenerateKeys();
                KeyStatusLabel.Text = $"Ключи готовы (n={_currentKeys.N}, e={_currentKeys.PublicKey})";
                KeyStatusLabel.Foreground = System.Windows.Media.Brushes.DarkBlue;
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Ошибка генерации: {ex.Message}", "Критическая ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        /// <summary>
        /// Обработчик события нажатия на кнопку "Зашифровать".
        /// </summary>
        /// <param name="sender">Объект, инициировавший событие (кнопка Шифрования).</param>
        /// <param name="e">Параметры события маршрутизации.</param>
        private void Encrypt_Click(object sender, RoutedEventArgs e)
        {
            if (_currentKeys == null)
            {
                MessageBox.Show("Сначала сгенерируйте ключи!", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            if (string.IsNullOrWhiteSpace(InputTextBox.Text))
            {
                MessageBox.Show("Поле ввода пусто.", "Внимание", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            try
            {
                string result = RSACipher.Encrypt(InputTextBox.Text, _currentKeys.PublicKey, _currentKeys.N);
                CipherTextBox.Text = result;

                DecryptedTextBox.Clear();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Ошибка: {ex.Message}", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        /// <summary>
        /// Обработчик события нажатия на кнопку "Дешифровать".
        /// </summary>
        /// <param name="sender">Объект, вызвавший событие (кнопка Дешифровать).</param>
        /// <param name="e">Параметры события маршрутизации.</param>
        private void Decrypt_Click(object sender, RoutedEventArgs e)
        {
            if (_currentKeys == null)
            {
                MessageBox.Show("Ключи отсутствуют.", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            try
            {
                string decrypted = RSACipher.Decrypt(CipherTextBox.Text, _currentKeys.PrivateKey, _currentKeys.N);
                DecryptedTextBox.Text = decrypted;
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Ошибка: {ex.Message}", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }
}
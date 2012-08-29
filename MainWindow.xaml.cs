using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.IO;

namespace OTPAuthorizer
{
	/// <summary>
	/// Interaction logic for MainWindow.xaml
	/// </summary>
	public partial class MainWindow : Window
	{
		private System.Timers.Timer timer;
		private List<AuthorizerEntry> authorizers;

		public MainWindow()
		{
			InitializeComponent();

			string[] keyStrings;

			string keyfile = "keys.txt";

			if (File.Exists(keyfile))
			{
				keyStrings = File.ReadAllLines(keyfile);
			}
			else
			{
				keyStrings = new[] { "otpauth://totp/Test%20Account:user1@example.com?secret=hen324SN4552nowenfnwererw", "otpauth://totp/bank.customer@example.com?period=15&digits=8&secret=abcdefghijklmnop234" };
			}

			authorizers = new List<AuthorizerEntry>();

			foreach (string keyString in keyStrings)
			{
				AuthorizerEntry newEntry = new AuthorizerEntry(keyString);
				authorizers.Add(newEntry);
				listBox.Items.Add(newEntry.Panel);
			}

			timer = new System.Timers.Timer(100);
			timer.Elapsed += new System.Timers.ElapsedEventHandler(timer_Elapsed);
			timer.Enabled = true;
		}

		void timer_Elapsed(object sender, System.Timers.ElapsedEventArgs e)
		{
			foreach (AuthorizerEntry authorizer in this.authorizers)
				authorizer.UpdateCodeAsync();
		}
	}
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using breuben.OTP;
using System.Windows.Controls;
using System.Windows;

namespace OTPAuthorizer
{
	class AuthorizerEntry
	{
		private AuthKey authKey;

		private StackPanel panel;
		private Label keyLabel;
		private Label codeLabel;
		private ProgressBar progressBar;

		public AuthorizerEntry(string uriString)
		{
			this.authKey = new AuthKey(uriString);
			initializeGuiElements();
			UpdateCodeAsync();
		}

		public Panel Panel { get { return this.panel; } }

		private void initializeGuiElements()
		{
			panel = new StackPanel();
			panel.Orientation = Orientation.Horizontal;

			keyLabel = new Label();
			keyLabel.FontWeight = FontWeights.Bold;
			keyLabel.Padding = new Thickness(5, 5, 5, 5);
			keyLabel.Width = 250;
			keyLabel.Content = authKey.Label;
			panel.Children.Add(keyLabel);

			codeLabel = new Label();
			codeLabel.FontSize = 14;
			codeLabel.Width = 90;
			panel.Children.Add(codeLabel);

			progressBar = new ProgressBar();
			progressBar.Width = 100;
			progressBar.Maximum = authKey.Period;
			panel.Children.Add(progressBar);
		}

		public delegate void UpdateCodeCallback(AuthCode authCode);

		public void UpdateCodeAsync()
		{
			AuthCode code = Authenticator.GenerateTOTP(this.authKey);
			codeLabel.Dispatcher.Invoke(new UpdateCodeCallback(this.UpdateCode), new object[] { code });
		}

		public void UpdateCode(AuthCode authCode)
		{
			progressBar.Value = authKey.Period - authCode.Age;
			if ((string)codeLabel.Content != authCode.Value)
				codeLabel.Content = authCode.Value;
		}
	}
}

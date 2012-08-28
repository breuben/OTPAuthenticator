using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Web;

namespace breuben.OTP
{
	public enum AuthType
	{
		HOTP,
		TOTP
	}

	public enum AlgorithmType
	{
		SHA1,
		SHA256,
		SHA512,
		MD5
	}

	public class AuthKey
	{
		public AuthType Type { get; set; }
		public string Label { get; set; }
		public byte[] Key { get; set; }
		private int _numDigits
		{
			get { return _numDigits; }
			set
			{
				if (value == 6 || value == 8)
					_numDigits = value;
				else
					throw new ArgumentException("Code digits may only be 6 or 8.");
			}
		}
		public int NumDigits { get; set; }
		private AlgorithmType _algorithmType = AlgorithmType.SHA1;
		public string Algorithm { get { return _algorithmType.ToString(); } }
		public int Period { get; set; }

		public AuthKey(string uriString)
		{
			Uri uri = new Uri(uriString);
			if (uri.Scheme != "otpauth")
				throw new ArgumentException("URI not of type otpauth.");

			AuthType authType;
			if (Enum.TryParse<AuthType>(uri.Host, true, out authType))
				this.Type = authType;
			else
				throw new ArgumentException(string.Format("Unsupported OTP Auth Type '{0}'", uri.Host));

			this.Label = HttpUtility.UrlDecode(uri.AbsolutePath.Substring(1));

			var parameters = HttpUtility.ParseQueryString(uri.Query);
			if (parameters.AllKeys.Contains("secret", StringComparer.InvariantCultureIgnoreCase))
				this.Key = Base32Decode(parameters["secret"]);
			else
				throw new ArgumentException("'secret' parameter required in otpauth URI.");

			if (parameters.AllKeys.Contains("digits", StringComparer.InvariantCultureIgnoreCase))
				this.NumDigits = Convert.ToInt32(parameters["digits"]);
			else
				this.NumDigits = 6;

			if (parameters.AllKeys.Contains("period", StringComparer.InvariantCultureIgnoreCase))
				this.Period = Convert.ToInt32(parameters["period"]);
			else
				this.Period = 30;

			if (parameters.AllKeys.Contains("algorithm", StringComparer.InvariantCultureIgnoreCase))
			{
				AlgorithmType otpAlgorithm;
				if (Enum.TryParse<AlgorithmType>(parameters["algorithm"], true, out otpAlgorithm))
					this._algorithmType = otpAlgorithm;
				else
					throw new ArgumentException(string.Format("Unsupported OTP Algorithm Type '{0}'", parameters["algorithm"]));
			}
			else
			{
				this._algorithmType = AlgorithmType.SHA1;
			}
		}

		public static byte[] Base32Decode(string base32String)
		{
			string base32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567abcdefghijklmnopqrstuvwxyz";
			List<byte> buffer = new List<byte>();

			int i = 0;
			foreach (char c in base32String)
			{
				if (c == '=')
					break;

				byte val = (byte)base32.IndexOf(c);
				if (val < 0x00)
					throw new ArgumentException("Invalid character in Base32 string.");

				if (val > 31)
					val -= 32;

				switch (i)
				{
					case 0:
						buffer.Add((byte)(val << 3));
						break;
					case 1:
						buffer[buffer.Count - 1] |= (byte)(val >> 2);
						buffer.Add((byte)(val << 6));
						break;
					case 2:
						buffer[buffer.Count - 1] |= (byte)(val << 1);
						break;
					case 3:
						buffer[buffer.Count - 1] |= (byte)(val >> 4);
						buffer.Add((byte)(val << 4));
						break;
					case 4:
						buffer[buffer.Count - 1] |= (byte)(val >> 1);
						buffer.Add((byte)(val << 7));
						break;
					case 5:
						buffer[buffer.Count - 1] |= (byte)(val << 2);
						break;
					case 6:
						buffer[buffer.Count - 1] |= (byte)(val >> 3);
						buffer.Add((byte)(val << 5));
						break;
					case 7:
						buffer[buffer.Count - 1] |= (byte)(val);
						break;
				}

				i++;
				if (i == 8)
					i = 0;
			}

			return buffer.ToArray();
		}
	}
}

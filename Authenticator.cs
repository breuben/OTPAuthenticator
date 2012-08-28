using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;

namespace breuben.OTP
{
	public class AuthCode
	{
		public string Value { get; set; }
		public double Age { get; set; }
	}

	class Authenticator
	{
		private static int[] DIGITS_POWER = { 1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000 };

		public static AuthCode GenerateTOTP(AuthKey key)
		{
			return GenerateTOTP(key, DateTime.UtcNow);
		}

		public static AuthCode GenerateTOTP(AuthKey key, DateTime dateTime)
		{
			byte[] T = getTfromTime(dateTime, key.Period);

			HMAC hmac = HMAC.Create("HMAC" + key.Algorithm);
			hmac.Key = key.Key;

			byte[] hash = hmac.ComputeHash(T);

			// put selected bytes into result int
			int offset = hash[hash.Length - 1] & 0xf;

			int binary = ((hash[offset] & 0x7f) << 24) | (hash[offset + 1] << 16) | (hash[offset + 2] << 8) | hash[offset + 3];

			int otp = binary % DIGITS_POWER[key.NumDigits];

			string totpString = Convert.ToString(otp);
			while (totpString.Length < key.NumDigits)
				totpString = "0" + totpString;

			return new AuthCode { Value = totpString, Age = getAgeFromTime(dateTime, key.Period) };
		}

		private static double getEpoch(DateTime dateTime)
		{
			return (dateTime - new DateTime(1970, 1, 1)).TotalSeconds;
		}

		private static byte[] getTfromTime(DateTime dateTime, int period = 30)
		{
			long epoch = (long)getEpoch(dateTime);
			long T = epoch / period;

			byte[] Tbytes = BitConverter.GetBytes(T);
			Array.Reverse(Tbytes);

			return Tbytes;
		}

		private static double getAgeFromTime(DateTime dateTime, int period = 30)
		{
			double epochDouble = getEpoch(dateTime);
			long epochLong = (long)epochDouble;

			double age = (int)(epochLong % period);
			age += (epochDouble - epochLong);
			return age;
		}
	}
}

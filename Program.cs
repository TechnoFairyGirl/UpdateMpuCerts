using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;

namespace UpdateMpuCerts
{
	sealed class Config
	{
		public string Url { get; set; }
		public string Username { get; set; }
		public string Password { get; set; }
		public string CertFile { get; set; }
		public string KeyFile { get; set; }
	}

	sealed class NoCheckCertificatePolicy : ICertificatePolicy
	{
		public bool CheckValidationResult(
			ServicePoint srvPoint, X509Certificate certificate, WebRequest request, int certificateProblem) =>
			true;
	}

	static class Program
	{
		static Config config;

		static string GetToken(string url, string username, string password)
		{
			using var clientHandler = new HttpClientHandler();
			clientHandler.AllowAutoRedirect = false;
			clientHandler.UseCookies = false;

			using var client = new HttpClient(clientHandler);

			using var content = new FormUrlEncodedContent(new Dictionary<string, string>
			{
				{ "action", "login" },
				{ "loginUsername", username },
				{ "loginPassword", password },
			});

			using var result = client.PostAsync($"{url.TrimEnd('/')}/login.php", content).Result;

			if (result.StatusCode != HttpStatusCode.Found)
				throw new UnauthorizedAccessException();

			var cookie = result.Headers.First(kvp => kvp.Key == "Set-Cookie").Value.First();
			var token = Regex.Match(cookie, "avctSessionId=([^;]*)").Groups[1].Value;

			return token;
		}

		static void UploadCert(string url, string token, string cert)
		{
			using var clientHandler = new HttpClientHandler();
			clientHandler.AllowAutoRedirect = false;
			clientHandler.UseCookies = false;

			using var client = new HttpClient(clientHandler);
			client.DefaultRequestHeaders.Add("Cookie", $"avctSessionId={token}");

			using var content = new MultipartFormDataContent();
			using var actionContent = new StringContent("commit");
			using var tokenContent = new StringContent(token);
			using var certContent = new StringContent(Convert.ToBase64String(Encoding.UTF8.GetBytes(cert)));
			content.Add(actionContent, "action");
			content.Add(tokenContent, "token");
			content.Add(certContent, "enccert");

			using var result = client.PostAsync($"{url.TrimEnd('/')}/managecertificate.php?cert=https", content).Result;

			if (result.StatusCode != HttpStatusCode.OK)
				throw new InvalidOperationException();
		}

		static void Reboot(string url, string token)
		{
			using var clientHandler = new HttpClientHandler();
			clientHandler.AllowAutoRedirect = false;
			clientHandler.UseCookies = false;

			using var client = new HttpClient(clientHandler);
			client.DefaultRequestHeaders.Add("Cookie", $"avctSessionId={token}");

			using var content = new FormUrlEncodedContent(new Dictionary<string, string>
			{
				{ "action", "reboot" },
				{ "token", token },
			});

			using var result = client.PostAsync($"{url.TrimEnd('/')}/appliance-overview.php", content).Result;

			if (result.StatusCode != HttpStatusCode.OK)
				throw new InvalidOperationException();
		}

		static void Main(string[] args)
		{
			var exePath = System.Reflection.Assembly.GetEntryAssembly().Location;
			var configPath = args.Length >= 1 ? args[0] : Path.Combine(Path.GetDirectoryName(exePath), "config.json");
			config = JsonConvert.DeserializeObject<Config>(File.ReadAllText(configPath));

			Console.WriteLine($"Updating SSL certificates on '{config.Url}'.");
			Console.WriteLine($"Cert file: {config.CertFile}");
			Console.WriteLine($"Key file: {config.KeyFile}");

			ServicePointManager.CertificatePolicy = new NoCheckCertificatePolicy();

			var token = GetToken(config.Url, config.Username, config.Password);

			Console.WriteLine($"Got token. ({token})");

			UploadCert(config.Url, token,
				File.ReadAllText(config.CertFile) + "\n" +
				File.ReadAllText(config.KeyFile));

			Console.WriteLine($"Uploaded certificate.");

			Reboot(config.Url, token);

			Console.WriteLine($"Reboot command sent.");
			Console.WriteLine($"Done.");
		}
	}
}

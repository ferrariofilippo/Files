// Copyright (c) Files Community
// Licensed under the MIT License.

namespace Files.App.ViewModels.Properties
{
    public sealed partial class SignaturesViewModel : ObservableObject, IDisposable
    {
		private IUserSettingsService UserSettingsService { get; } = Ioc.Default.GetRequiredService<IUserSettingsService>();

		private CancellationTokenSource _cancellationTokenSource;

		public ObservableCollection<SignatureInfoItem> Signatures { get; set; }

		public SignaturesViewModel(ListedItem item)
		{
			_cancellationTokenSource = new();
			Signatures = new() { new SignatureInfoItem() };
		}

		public void Dispose()
		{
			_cancellationTokenSource.Cancel();
		}
	}
}

﻿// Copyright (c) 2024 Files Community
// Licensed under the MIT License. See the LICENSE.

namespace Files.App.Actions
{
	internal sealed class DeleteItemPermanentlyAction : BaseDeleteAction, IAction
	{
		public string Label
			=> "DeletePermanently".GetLocalizedResource();

		public string Description
			=> "DeleteItemPermanentlyDescription".GetLocalizedResource();

		public HotKey HotKey
			=> new(Keys.Delete, KeyModifiers.Shift);

		public Task ExecuteAsync(object? parameter = null)
		{
			return DeleteItemsAsync(true);
		}
	}
}

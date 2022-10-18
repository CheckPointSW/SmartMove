/********************************************************************
Copyright (c) 2017, Check Point Software Technologies Ltd.
All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
********************************************************************/

using System.Windows.Controls;
using Microsoft.Xaml.Behaviors;

namespace SmartMove
{
    /// <summary>
    /// Selects all text when TextBox is clicked 3 times in a row (triple click).
    /// </summary>
    public class TripleClickSelectsAllTextBehavior : Behavior<TextBox>
    {
        #region Overrides

        protected override void OnAttached()
        {
            base.OnAttached();

            AssociatedObject.PreviewMouseLeftButtonDown += OnTextBoxPreviewMouseLeftButtonDown;
            AssociatedObject.LostFocus += OnTextBoxLostFocus;
        }

        protected override void OnDetaching()
        {
            base.OnDetaching();

            AssociatedObject.PreviewMouseLeftButtonDown -= OnTextBoxPreviewMouseLeftButtonDown;
            AssociatedObject.LostFocus -= OnTextBoxLostFocus;
        }

        #endregion

        #region Event Handlers

        private void OnTextBoxPreviewMouseLeftButtonDown(object sender, System.Windows.Input.MouseButtonEventArgs e)
        {
            if (e.ClickCount == 3)
            {
                AssociatedObject.SelectAll();
                e.Handled = true;
            }
        }

        private void OnTextBoxLostFocus(object sender, System.Windows.RoutedEventArgs e)
        {
            AssociatedObject.Select(0, 0);
        }

        #endregion
    }
}

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

using System.Windows;
using System.Windows.Input;

namespace SmartMove
{
    /// <summary>
    /// Interaction logic for MessageWindow.xaml
    /// </summary>
    public partial class MessageWindow : Window
    {
        #region Construction

        public MessageWindow()
        {
            InitializeComponent();
        }

        #endregion

        #region Properties

        #region Message

        public string Message
        {
            get { return (string)GetValue(MessageProperty); }
            set { SetValue(MessageProperty, value); }
        }

        public static readonly DependencyProperty MessageProperty =
            DependencyProperty.Register("Message", typeof(string), typeof(MessageWindow), new PropertyMetadata(null));

        #endregion

        #region MessageType

        public MessageTypes MessageType
        {
            get { return (MessageTypes)GetValue(MessageTypeProperty); }
            set { SetValue(MessageTypeProperty, value); }
        }

        public static readonly DependencyProperty MessageTypeProperty =
            DependencyProperty.Register("MessageType", typeof(MessageTypes), typeof(MessageWindow), new PropertyMetadata(MessageTypes.Error));

        #endregion

        #endregion

        #region Event Handlers

        private void CloseButton_OnClick(object sender, RoutedEventArgs e)
        {
            Close();
        }

        private void HeaderPanel_OnMouseDown(object sender, MouseButtonEventArgs e)
        {
            if (e.ChangedButton == MouseButton.Left && e.LeftButton == MouseButtonState.Pressed)
            {
                DragMove();
            }
        }

        #endregion
    }

    public enum MessageTypes
    {
        Error,
        Warning,
        Info
    }
}

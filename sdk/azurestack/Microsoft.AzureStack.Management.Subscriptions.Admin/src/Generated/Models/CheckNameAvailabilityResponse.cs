// <auto-generated>
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for
// license information.
//
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is
// regenerated.
// </auto-generated>

namespace Microsoft.AzureStack.Management.Subscriptions.Admin.Models
{
    using Newtonsoft.Json;
    using System.Linq;

    /// <summary>
    /// The check name availability response definition
    /// </summary>
    public partial class CheckNameAvailabilityResponse
    {
        /// <summary>
        /// Initializes a new instance of the CheckNameAvailabilityResponse
        /// class.
        /// </summary>
        public CheckNameAvailabilityResponse()
        {
            CustomInit();
        }

        /// <summary>
        /// Initializes a new instance of the CheckNameAvailabilityResponse
        /// class.
        /// </summary>
        /// <param name="nameAvailable">A value indicating whether the name is
        /// available.</param>
        /// <param name="reason">The reason for the unavailability of the name.
        /// Possible values include: 'Invalid', 'AlreadyExists'</param>
        /// <param name="message">The message explaining the reason.</param>
        public CheckNameAvailabilityResponse(bool? nameAvailable = default(bool?), string reason = default(string), string message = default(string))
        {
            NameAvailable = nameAvailable;
            Reason = reason;
            Message = message;
            CustomInit();
        }

        /// <summary>
        /// An initialization method that performs custom operations like setting defaults
        /// </summary>
        partial void CustomInit();

        /// <summary>
        /// Gets or sets a value indicating whether the name is available.
        /// </summary>
        [JsonProperty(PropertyName = "nameAvailable")]
        public bool? NameAvailable { get; set; }

        /// <summary>
        /// Gets or sets the reason for the unavailability of the name.
        /// Possible values include: 'Invalid', 'AlreadyExists'
        /// </summary>
        [JsonProperty(PropertyName = "reason")]
        public string Reason { get; set; }

        /// <summary>
        /// Gets or sets the message explaining the reason.
        /// </summary>
        [JsonProperty(PropertyName = "message")]
        public string Message { get; set; }

    }
}

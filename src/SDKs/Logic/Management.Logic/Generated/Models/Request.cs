// <auto-generated>
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for
// license information.
//
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is
// regenerated.
// </auto-generated>

namespace Microsoft.Azure.Management.Logic.Models
{
    using Newtonsoft.Json;
    using System.Linq;

    /// <summary>
    /// A request.
    /// </summary>
    public partial class Request
    {
        /// <summary>
        /// Initializes a new instance of the Request class.
        /// </summary>
        public Request()
        {
            CustomInit();
        }

        /// <summary>
        /// Initializes a new instance of the Request class.
        /// </summary>
        /// <param name="headers">A list of all the headers attached to the
        /// request.</param>
        /// <param name="uri">The destination for the request.</param>
        /// <param name="method">The HTTP method used for the request.</param>
        public Request(object headers = default(object), string uri = default(string), string method = default(string))
        {
            Headers = headers;
            Uri = uri;
            Method = method;
            CustomInit();
        }

        /// <summary>
        /// An initialization method that performs custom operations like setting defaults
        /// </summary>
        partial void CustomInit();

        /// <summary>
        /// Gets or sets a list of all the headers attached to the request.
        /// </summary>
        [JsonProperty(PropertyName = "headers")]
        public object Headers { get; set; }

        /// <summary>
        /// Gets or sets the destination for the request.
        /// </summary>
        [JsonProperty(PropertyName = "uri")]
        public string Uri { get; set; }

        /// <summary>
        /// Gets or sets the HTTP method used for the request.
        /// </summary>
        [JsonProperty(PropertyName = "method")]
        public string Method { get; set; }

    }
}
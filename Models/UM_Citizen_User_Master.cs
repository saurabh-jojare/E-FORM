//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated from a template.
//
//     Manual changes to this file may cause unexpected behavior in your application.
//     Manual changes to this file will be overwritten if the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace EFORM.Models
{
    using System;
    using System.Collections.Generic;
    
    public partial class UM_Citizen_User_Master
    {
        public long CitizenID { get; set; }
        public string MobileNo { get; set; }
        public string IMEINo { get; set; }
        public string Name { get; set; }
        public string Address { get; set; }
        public string Email { get; set; }
        public bool IsActive { get; set; }
        public System.DateTime EntryDate { get; set; }
        public string Password { get; set; }
        public Nullable<int> StateCode { get; set; }
        public Nullable<int> DistrictCode { get; set; }
        public Nullable<int> BlockCode { get; set; }
    
        public virtual MASTER_BLOCK MASTER_BLOCK { get; set; }
        public virtual MASTER_DISTRICT MASTER_DISTRICT { get; set; }
        public virtual MASTER_STATE MASTER_STATE { get; set; }
    }
}
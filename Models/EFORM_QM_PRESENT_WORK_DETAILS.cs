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
    
    public partial class EFORM_QM_PRESENT_WORK_DETAILS
    {
        public int WORK_ID { get; set; }
        public int DETAIL_ID { get; set; }
        public int ADMIN_ND_CODE { get; set; }
        public int QM_USER_ID { get; set; }
        public int PR_ROAD_CODE { get; set; }
        public short ITEM_ID { get; set; }
        public Nullable<decimal> ROAD_FROM { get; set; }
        public Nullable<decimal> ROAD_TO { get; set; }
        public string IPADD { get; set; }
    
        public virtual ADMIN_DEPARTMENT ADMIN_DEPARTMENT { get; set; }
        public virtual EFORM_MASTER EFORM_MASTER { get; set; }
        public virtual EFORM_MASTER_WORK_ITEM EFORM_MASTER_WORK_ITEM { get; set; }
        public virtual IMS_SANCTIONED_PROJECTS IMS_SANCTIONED_PROJECTS { get; set; }
        public virtual UM_User_Master UM_User_Master { get; set; }
    }
}
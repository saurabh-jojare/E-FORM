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
    
    public partial class EFORM_PIU_PREVIOUS_INSP_DETAILS
    {
        public int INSP_ID { get; set; }
        public int DETAIL_ID { get; set; }
        public int ADMIN_ND_CODE { get; set; }
        public int PIU_USER_ID { get; set; }
        public int PR_ROAD_CODE { get; set; }
        public System.DateTime VISIT_DATE { get; set; }
        public string VISITOR_NAME_DESG { get; set; }
        public Nullable<decimal> ROAD_FROM { get; set; }
        public Nullable<decimal> ROAD_TO { get; set; }
        public string INSP_LEVEL { get; set; }
        public string OBSERVATIONS { get; set; }
        public string ACTION { get; set; }
        public string IPADD { get; set; }
    
        public virtual ADMIN_DEPARTMENT ADMIN_DEPARTMENT { get; set; }
        public virtual EFORM_MASTER EFORM_MASTER { get; set; }
        public virtual IMS_SANCTIONED_PROJECTS IMS_SANCTIONED_PROJECTS { get; set; }
        public virtual UM_User_Master UM_User_Master { get; set; }
    }
}
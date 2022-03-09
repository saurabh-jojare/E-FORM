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
    
    public partial class EFORM_QM_QC_TEST_DETAILS
    {
        public int WORK_ID { get; set; }
        public int INFO_ID { get; set; }
        public short ITEM_ID { get; set; }
        public Nullable<decimal> DPR_QUANTITY { get; set; }
        public Nullable<decimal> EXECUTED_QUANTITY { get; set; }
        public string TEST_NAME { get; set; }
        public Nullable<int> REQD_TEST_NUMBER { get; set; }
        public Nullable<int> CONDUCTED_TEST_NUMBER { get; set; }
        public string IS_TESTING_ADEQUATE { get; set; }
        public string IPADD { get; set; }
        public int PR_ROAD_CODE { get; set; }
    
        public virtual EFORM_MASTER_WORK_ITEM EFORM_MASTER_WORK_ITEM { get; set; }
        public virtual EFORM_QM_QC_TEST_DETAILS EFORM_QM_QC_TEST_DETAILS1 { get; set; }
        public virtual EFORM_QM_QC_TEST_DETAILS EFORM_QM_QC_TEST_DETAILS2 { get; set; }
        public virtual IMS_SANCTIONED_PROJECTS IMS_SANCTIONED_PROJECTS { get; set; }
    }
}

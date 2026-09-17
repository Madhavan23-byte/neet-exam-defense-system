import React, { useEffect, useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import {
  CheckCircle2, FileText, Printer, ArrowRight, Home, Shield,
  Clock, Calendar, UserCheck
} from 'lucide-react';
import { useExamSessionStore } from '../../stores/examStore';
import { candidateApi } from '../../services/api';
import PortalHeader from '../../components/ui/PortalHeader';
import PortalFooter from '../../components/ui/PortalFooter';

export default function ResultPage() {
  const navigate = useNavigate();
  const { sessionToken, clearSession } = useExamSessionStore();

  const [resultData, setResultData] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    if (!sessionToken) {
      navigate('/candidate/login');
      return;
    }

    const fetchResult = async () => {
      setLoading(true);
      try {
        const res = await candidateApi.getResult(sessionToken);
        setResultData(res.data);
      } catch (err: any) {
        setError(err?.response?.data?.detail || err.message || 'Error fetching submission details');
      } finally {
        setLoading(false);
      }
    };

    fetchResult();
  }, [sessionToken, navigate]);

  const handlePrint = () => {
    window.print();
  };

  const handleExit = () => {
    clearSession();
    navigate('/');
  };

  return (
    <div className="min-h-screen flex flex-col bg-[var(--gov-canvas)]">
      <PortalHeader subtitle="Examination Submission Confirmation" />

      <main className="flex-1 max-w-3xl mx-auto px-4 py-10 w-full">
        {loading ? (
          <div className="py-20 text-center text-slate-500 text-xs">
            Retrieving submission verification from server...
          </div>
        ) : error ? (
          <div className="gov-card border-red-200 bg-red-50 text-red-700 text-xs p-5">
            <h2 className="font-bold text-sm mb-1">Unable to load submission receipt</h2>
            <p>{error}</p>
          </div>
        ) : (
          <div className="space-y-6">
            {/* Official Submission Slip Card */}
            <div className="gov-card-elevated border-[var(--gov-border)]">
              <div className="text-center pb-6 border-b border-[var(--gov-border)]">
                <div className="w-12 h-12 rounded-full bg-emerald-50 text-emerald-700 border border-emerald-200 flex items-center justify-center mx-auto mb-3">
                  <CheckCircle2 className="w-6 h-6" />
                </div>
                <h1 className="text-xl font-bold text-[var(--gov-navy-dark)]">
                  Examination Successfully Submitted
                </h1>
                <p className="text-xs text-slate-500 mt-1">
                  Your examination session has been recorded and safely concluded on the secure server.
                </p>
              </div>

              {/* Verified Fields (Constraint 3: strictly verified backend data) */}
              <div className="py-6 space-y-3 text-xs border-b border-[var(--gov-border)]">
                <div className="flex justify-between py-1 border-b border-stone-100">
                  <span className="text-slate-500 font-semibold">Session Identifier:</span>
                  <span className="font-mono text-slate-800 font-semibold">{resultData?.session_id || '—'}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-stone-100">
                  <span className="text-slate-500 font-semibold">Candidate ID:</span>
                  <span className="font-mono text-slate-800">{resultData?.candidate_id || '—'}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-stone-100">
                  <span className="text-slate-500 font-semibold">Examination Code:</span>
                  <span className="font-mono text-slate-800">{resultData?.exam_id || '—'}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-stone-100">
                  <span className="text-slate-500 font-semibold">Session Status:</span>
                  <span className="badge-secure">{resultData?.status || 'SUBMITTED'}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-stone-100">
                  <span className="text-slate-500 font-semibold">Submission Timestamp:</span>
                  <span className="font-mono text-slate-800">
                    {resultData?.submitted_at
                      ? new Date(resultData.submitted_at).toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' }) + ' IST'
                      : '—'}
                  </span>
                </div>

                {resultData?.result_available && (
                  <>
                    <div className="flex justify-between py-1 border-b border-stone-100">
                      <span className="text-slate-500 font-semibold">Questions Attempted:</span>
                      <span className="font-bold text-slate-800">{resultData.attempted ?? '—'}</span>
                    </div>
                    {resultData.total_score !== undefined && (
                      <div className="flex justify-between py-1 border-b border-stone-100">
                        <span className="text-slate-500 font-semibold">Calculated Score:</span>
                        <span className="font-bold text-emerald-800">
                          {resultData.total_score} / {resultData.max_score || '—'}
                        </span>
                      </div>
                    )}
                  </>
                )}
              </div>

              {/* Informative Guidance */}
              <div className="pt-4 text-xs text-slate-600 space-y-2">
                <p className="font-medium text-[var(--gov-navy-dark)]">Candidate Acknowledgement Notice:</p>
                <p className="leading-relaxed">
                  Please retain this acknowledgement confirmation for your records. Official scoring normalization and merit ranks will be announced following review by the Examination Directorate.
                </p>
              </div>

              {/* Action Buttons */}
              <div className="mt-6 pt-4 border-t border-[var(--gov-border)] flex flex-wrap items-center justify-between gap-3">
                <button
                  type="button"
                  onClick={handlePrint}
                  className="btn btn-outline text-xs"
                >
                  <Printer className="w-3.5 h-3.5" /> Print Acknowledgement
                </button>
                <button
                  type="button"
                  onClick={handleExit}
                  className="btn btn-primary text-xs"
                >
                  <Home className="w-3.5 h-3.5" /> Exit to Homepage
                </button>
              </div>
            </div>
          </div>
        )}
      </main>

      <PortalFooter />
    </div>
  );
}

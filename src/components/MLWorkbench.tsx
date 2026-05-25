/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect } from "react";
import { Terminal, Cpu, Play, RefreshCw, BarChart2, CheckCircle, Flame, Layers, AlertCircle } from "lucide-react";
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer } from "recharts";
import { UserRole } from "../types.js";

interface MLWorkbenchProps {
  currentUserRole?: UserRole;
  token: string;
}

export function MLWorkbench({ currentUserRole, token }: MLWorkbenchProps) {
  // Config states
  const [epochs, setEpochs] = useState("100");
  const [learningRate, setLearningRate] = useState("0.4");
  const [trainingLogs, setTrainingLogs] = useState<any[]>([]);
  const [featureImportances, setFeatureImportances] = useState<any[]>([]);

  // Performance stats state
  const [accuracy, setAccuracy] = useState(0.91);
  const [precision, setPrecision] = useState(0.88);
  const [recall, setRecall] = useState(0.93);
  const [f1, setF1] = useState(0.90);
  const [confusionMatrix, setConfusionMatrix] = useState({ tp: 5, fp: 1, tn: 5, fn: 1 });

  // System states
  const [training, setTraining] = useState(false);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Fetch initial model metadata
  useEffect(() => {
    fetchWeights();
  }, []);

  const fetchWeights = async () => {
    try {
      const response = await fetch("/api/ml/weights", {
        headers: { "Authorization": `Bearer ${token}` }
      });
      const data = await response.json();
      if (response.ok) {
        setFeatureImportances(data.featureImportance || []);
      }
    } catch (err) {
      console.error("Failed to load model coefficients:", err);
    }
  };

  const handleRetrain = async (e: React.FormEvent) => {
    e.preventDefault();
    setTraining(true);
    setSuccessMsg(null);
    setError(null);

    try {
      const response = await fetch("/api/ml/retrain", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`
        },
        body: JSON.stringify({
          epochs: parseInt(epochs),
          learningRate: parseFloat(learningRate)
        })
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || "ML compiling sequence failure.");
      }

      // Update parameters
      setAccuracy(data.accuracy);
      setPrecision(data.precision);
      setRecall(data.recall);
      setF1(data.f1);
      setConfusionMatrix(data.confusionMatrix);
      setTrainingLogs(data.epochsLogs || []);
      setFeatureImportances(data.featureImportance || []);

      setSuccessMsg(`Model successfully compiled! New F1 score output: ${(data.f1 * 100).toFixed(1)}%`);
    } catch (err: any) {
      setError(err.message || "Model compilation failed.");
    } finally {
      setTraining(false);
    }
  };

  return (
    <div className="space-y-8 font-sans">
      {/* HEADER SECTION */}
      <div className="border-b border-slate-800/60 pb-5">
        <h2 className="text-xl font-bold text-white flex items-center gap-2">
          <Cpu className="w-5.5 h-5.5 text-cyan-400" /> Machine Learning Workbench
        </h2>
        <p className="text-xs text-slate-500">Configure parameters, retrain TF-IDF logistic classifiers, and inspect real-time neural gradients and decision boundaries</p>
      </div>

      {successMsg && (
        <div className="p-3 bg-cyan-500/10 border border-cyan-500/30 rounded-lg text-cyan-400 text-xs font-mono text-center">
          [SYS_SUCCESS]: {successMsg}
        </div>
      )}

      {error && (
        <div className="p-3 bg-rose-500/10 border border-rose-500/30 rounded-lg text-rose-450 text-xs font-mono text-center">
          [ML_COMPILE_ERROR]: {error}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* HYPERPARAMETERS FORM PANEL */}
        <form onSubmit={handleRetrain} className="bg-[#0b111a]/45 border border-slate-800 p-6 rounded-2xl space-y-5 flex flex-col justify-between">
          <div className="space-y-4">
            <h3 className="text-sm font-bold text-slate-200 uppercase font-mono tracking-wide border-b border-slate-800 pb-2 flex items-center gap-2">
              <Layers className="w-4.5 h-4.5 text-cyan-400" /> Neural Classifier Parameters
            </h3>

            {/* Epochs */}
            <div>
              <label className="block text-xs font-mono uppercase text-slate-400 mb-1">Epoch Runs (Iterations)</label>
              <input
                type="number"
                min="10"
                max="500"
                value={epochs}
                onChange={(e) => setEpochs(e.target.value)}
                className="w-full px-4 py-2.5 bg-[#05070a] border border-slate-850 rounded-xl text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500/70"
                placeholder="200"
              />
              <span className="text-[10px] text-slate-600 font-mono mt-1 block">Value range: 10 - 500 gradient steps</span>
            </div>

            {/* Learning Rate */}
            <div>
              <label className="block text-xs font-mono uppercase text-slate-400 mb-1">Gradient Learning Rate (η)</label>
              <input
                type="number"
                step="0.05"
                min="0.05"
                max="1.5"
                value={learningRate}
                onChange={(e) => setLearningRate(e.target.value)}
                className="w-full px-4 py-2.5 bg-[#05070a] border border-slate-850 rounded-xl text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500/70"
                placeholder="0.4"
              />
              <span className="text-[10px] text-slate-600 font-mono mt-1 block">Recommended range: 0.1 - 1.0 step adjustments</span>
            </div>

            <div className="bg-slate-950/60 p-3.5 border border-slate-850 rounded-xl text-[10px] font-mono text-slate-500 leading-relaxed text-justify space-y-2">
              <div className="flex gap-1.5 text-amber-500 font-bold"><AlertCircle className="w-4 h-4 shrink-0" /> Note on Training Dataset:</div>
              <p>
                Retraining occurs on-demand using academic threat profiles stored in the JSON DB. On completion, the server compiles the vectors, updates indices coefficients and persists weights to host storage modules.
              </p>
            </div>
          </div>

          <button
            type="submit"
            disabled={training}
            className="w-full mt-6 flex items-center justify-center gap-2 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 border border-cyan-400/30 text-white font-bold py-3 px-4 rounded-xl shadow-[0_4px_15px_rgba(6,182,212,0.15)] cursor-pointer transition-all disabled:opacity-50 text-xs font-mono"
          >
            {training ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin-slow" /> Running Gradient Steps...
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5 fill-current animate-pulse animate-duration-1000" /> Re-Compile Model weights ➔
              </>
            )}
          </button>
        </form>

        {/* CLASSIFIER STATS & MATRIX */}
        <div className="lg:col-span-2 space-y-6">
          {/* Metrics grids */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <div className="bg-slate-950 border border-slate-800 p-4 rounded-xl text-center">
              <span className="text-[10px] font-mono text-slate-500 block">Accuracy (VAL)</span>
              <span className="text-xl font-extrabold text-white font-mono block mt-1">{(accuracy * 100).toFixed(1)}%</span>
            </div>
            <div className="bg-slate-950 border border-slate-800 p-4 rounded-xl text-center">
              <span className="text-[10px] font-mono text-slate-500 block">Precision Ratio</span>
              <span className="text-xl font-bold text-slate-300 font-mono block mt-1">{(precision * 100).toFixed(1)}%</span>
            </div>
            <div className="bg-slate-950 border border-slate-800 p-4 rounded-xl text-center">
              <span className="text-[10px] font-mono text-slate-500 block">Sensitivity (Recall)</span>
              <span className="text-xl font-bold text-slate-300 font-mono block mt-1">{(recall * 100).toFixed(1)}%</span>
            </div>
            <div className="bg-slate-950 border border-slate-850 p-4 rounded-xl text-center bg-gradient-to-br from-cyan-950/20 to-slate-950">
              <span className="text-[10px] font-mono text-cyan-400 block font-bold">F1 Classifier Score</span>
              <span className="text-xl font-extrabold text-cyan-400 font-mono block mt-1">{(f1 * 100).toFixed(1)}%</span>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Confusion Matrix */}
            <div className="bg-[#0b111a]/45 border border-slate-800 p-6 rounded-2xl space-y-4">
              <h3 className="text-xs font-bold text-slate-200 uppercase font-mono tracking-wide">Model Confusion Matrix Grid</h3>
              
              <div className="grid grid-cols-2 gap-2 text-center font-mono text-xs">
                {/* TP */}
                <div className="p-3 bg-cyan-500/5 border border-cyan-500/15 rounded-lg">
                  <span className="block text-[10px] text-slate-500">True Positives (TP)</span>
                  <span className="text-lg font-bold text-cyan-450 mt-1 block">{confusionMatrix.tp}</span>
                  <span className="text-[9px] text-slate-600 block mt-0.5">Threat correctly caught</span>
                </div>

                {/* FP */}
                <div className="p-3 bg-rose-500/5 border border-rose-500/15 rounded-lg">
                  <span className="block text-[10px] text-slate-500">False Positives (FP)</span>
                  <span className="text-lg font-bold text-rose-450 mt-1 block">{confusionMatrix.fp}</span>
                  <span className="text-[9px] text-slate-650 block mt-0.5">Safe mail flagged</span>
                </div>

                {/* FN */}
                <div className="p-3 bg-rose-500/5 border border-rose-500/15 rounded-lg">
                  <span className="block text-[10px] text-slate-500">False Negatives (FN)</span>
                  <span className="text-lg font-bold text-rose-450 mt-1 block">{confusionMatrix.fn}</span>
                  <span className="text-[9px] text-slate-655 block mt-0.5">Threat slipped through</span>
                </div>

                {/* TN */}
                <div className="p-3 bg-cyan-500/5 border border-cyan-500/15 rounded-lg">
                  <span className="block text-[10px] text-slate-500">True Negatives (TN)</span>
                  <span className="text-lg font-bold text-cyan-450 mt-1 block">{confusionMatrix.tn}</span>
                  <span className="text-[9px] text-slate-600 block mt-0.5">Safe correctly passed</span>
                </div>
              </div>
            </div>

            {/* Gradient Loss chart Recharts */}
            <div className="bg-[#0b111a]/45 border border-slate-800 p-6 rounded-2xl flex flex-col justify-between">
              <div>
                <h3 className="text-xs font-bold text-slate-200 uppercase font-mono tracking-wide">Binary Cross Entropy loss</h3>
                <p className="text-[10px] text-slate-500">Log Loss convergence rate over training epoch run milestones</p>
              </div>

              <div className="h-44 w-full">
                {trainingLogs.length > 0 ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={trainingLogs} margin={{ top: 10, right: 10, left: -30, bottom: 0 }}>
                      <XAxis dataKey="epoch" stroke="#475569" fontSize={9} />
                      <YAxis stroke="#475569" fontSize={9} />
                      <Tooltip contentStyle={{ backgroundColor: "#0f172a", border: "1px solid #334155", color: "#f8fafc" }} />
                      <Line type="monotone" dataKey="loss" stroke="#06b6d4" strokeWidth={2} dot={false} name="Loss" />
                    </LineChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="h-full flex items-center justify-center text-slate-650 font-mono text-[10px]">
                    [No logs. Click "Re-Compile Model" to view Loss Chart]
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* 3. COEFFICIENTS CHART TABLE */}
      <section className="bg-[#0b111a]/45 border border-slate-800 rounded-2xl p-6 space-y-4">
        <div>
          <h3 className="text-sm font-bold text-slate-200 uppercase font-mono tracking-wide">Classifier Feature Coefficients Registry</h3>
          <p className="text-xs text-slate-500 mt-0.5 font-sans">
            Full list of TF-IDF vocabulary weights currently cached in system memory. High positive coefficient weights represent phishing features, negative values indicate legitimate features.
          </p>
        </div>

        {/* Weights listing */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          {featureImportances.length > 0 ? (
            featureImportances.slice(0, 15).map((feat, idx) => {
              const isPhishFeat = feat.coefficient > 0;
              return (
                <div key={idx} className="bg-[#05070a] p-3 rounded-xl border border-slate-850 flex items-center justify-between text-xs font-mono">
                  <div className="font-semibold text-slate-250 truncate pr-2 max-w-[150px]">{feat.word}</div>
                  <div className={`font-bold shrink-0 ${isPhishFeat ? "text-rose-500" : "text-cyan-400"}`}>
                    {isPhishFeat ? `+${feat.coefficient.toFixed(2)}` : `${feat.coefficient.toFixed(2)}`}
                  </div>
                </div>
              );
            })
          ) : (
            <div className="col-span-3 text-center py-6 text-slate-600 text-xs font-mono">No feature weights found. Click Re-Compile to index vocabulary.</div>
          )}
        </div>
      </section>
    </div>
  );
}
